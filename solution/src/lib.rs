mod domain;

use std::{collections::HashMap, future::Future, pin::Pin, sync::Arc};

pub use crate::domain::*;
pub use atomic_register_public::*;
use hmac::{Hmac, Mac};
pub use register_client_public::*;
pub use sectors_manager_public::*;
use sha2::Sha256;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
pub use transfer_public::*;
use uuid::Uuid;

type ShortcutChannel = tokio::sync::mpsc::Sender<(
    RegisterCommand,
    bool,
    Option<tokio::sync::mpsc::Sender<Vec<u8>>>,
)>;
enum ChannelMessage {
    FromTcp(
        (
            RegisterCommand,
            bool,
            Option<tokio::sync::mpsc::Sender<Vec<u8>>>,
        ),
    ),
    AtomRegisterFinished,
}

struct SystemAck {
    process_identifier: u8,
    msg_type: u8,
    msg_ident: Uuid,
}

pub async fn run_register_process(config: Configuration) {
    // set TCP listener
    let tcp_locations = config.public.tcp_locations.clone();
    let listener =
        tokio::net::TcpListener::bind(tcp_locations[config.public.self_rank as usize - 1].clone())
            .await
            .unwrap();

    // make sectors manager
    // make sub_dir for sectors manager
    let sub_dir = format!("register_client_{}", config.public.self_rank);
    let storage_dir = config.public.storage_dir.join(sub_dir);
    tokio::fs::create_dir_all(&storage_dir).await.unwrap();
    let sectors_manager = sectors_manager_public::build_sectors_manager(storage_dir).await;

    // channel for getting deserialized commands
    let (deserialized_msg_tx, mut general_incoming_receiver) = tokio::sync::mpsc::channel::<(
        RegisterCommand,
        bool,
        Option<tokio::sync::mpsc::Sender<Vec<u8>>>,
    )>(
        100, // ^ we only need this channel for CLIENT commands not for SYSTEM commands
    );

    // build register client
    let register_client_struct = register_client_public::RegisterClientStruct::new(
        config.public.tcp_locations.clone(),
        config.hmac_system_key,
        config.public.self_rank,
        deserialized_msg_tx.clone(),
    )
    .await;
    let register_client_arc: Arc<dyn register_client_public::RegisterClient> =
        Arc::new(register_client_struct);

    // convert n_sectors to machine byte order
    let n_sectors = config.public.n_sectors.to_ne_bytes();
    let n_sectors = u64::from_ne_bytes(n_sectors);

    // spawn task for accepting new TCP connections
    tokio::spawn(async move {
        // loop for accepting new TCP connections
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();

            // clone channels for accessing them in the task
            let tx = deserialized_msg_tx.clone();

            // spawn task for accessing the stream
            tokio::spawn(async move {
                let (callback_channel_tx, mut callback_channel_rx) =
                    tokio::sync::mpsc::channel::<Vec<u8>>(10);
                loop {
                    // read the message from TCP or send the data
                    tokio::select! {
                        // read the message from CLIENT or SYSTEM on TCP
                        result = deserialize_register_command(
                            &mut stream,
                            &config.hmac_system_key,
                            &config.hmac_client_key,
                        ) => {
                            match result{
                                Ok((cmd, is_ok)) => {
                                    // send deserialized command to manager
                                    // sent ack only if this is system command
                                    if let RegisterCommand::System(sys_cmd) = &cmd {
                                        let response = make_and_serialize_system_ack(
                                            sys_cmd,
                                            config.public.self_rank,
                                            &config.hmac_system_key,
                                        ).await;
                                        stream.write_all(&response).await.unwrap();
                                        stream.flush().await.unwrap();
                                    }

                                    // send deserialized command to manager
                                    tx.send((cmd, is_ok, Some(callback_channel_tx.clone()))).await.unwrap();
                                }
                                Err(_) => {
                                    // ignore the message
                                }
                            }
                        }
                        // send the data to the CLIENT
                        data = callback_channel_rx.recv() => {
                            if let Some(data) = data {
                                stream.write_all(&data).await.unwrap();
                                stream.flush().await.unwrap();
                            }
                        }
                    }
                }
            });
        }
    });

    // map for channels for routing the commands to the correct atomic register's task
    let mut atomic_register_channels = HashMap::new();

    // spawn task for routing the commands to the correct atomic register's task
    // tokio::spawn(async move {
    loop {
        let (cmd, is_ok, callback_channel_tx) = general_incoming_receiver.recv().await.unwrap();
        let sector_idx = match cmd {
            RegisterCommand::Client(ClientRegisterCommand { header, .. }) => header.sector_idx,
            RegisterCommand::System(SystemRegisterCommand { header, .. }) => header.sector_idx,
        };

        // check if the command is valid
        if is_command_valid_handle_invalid(
            cmd.clone(),
            is_ok,
            callback_channel_tx.clone(),
            &config.hmac_client_key,
            n_sectors,
        )
        .await
        {
            let channel_message =
                ChannelMessage::FromTcp((cmd.clone(), is_ok, callback_channel_tx));

            // check if theree is atomic register for this sector and if not create it
            if let std::collections::hash_map::Entry::Vacant(e) =
                atomic_register_channels.entry(sector_idx)
            {
                // spawn task for atomic register

                // make atomic register
                let atomic_register = atomic_register_public::build_atomic_register(
                    config.public.self_rank,
                    sector_idx,
                    Arc::clone(&register_client_arc),
                    Arc::clone(&sectors_manager),
                    config.public.tcp_locations.len() as u8,
                )
                .await;

                // create channels for routing the commands to the correct atomic register's task
                let (ar_tx, ar_rx) = tokio::sync::mpsc::channel::<ChannelMessage>(10);
                e.insert(ar_tx.clone());

                // spawn task for atomic register
                spawn_task_for_atomic_register(
                    ar_rx,
                    ar_tx,
                    atomic_register,
                    config.hmac_client_key,
                );
            }

            // send the command to the correct atomic register's task
            atomic_register_channels
                .get(&sector_idx)
                .unwrap()
                .send(channel_message)
                .await
                .unwrap();
        }
    }
    // });
}

fn spawn_task_for_atomic_register(
    mut ar_rx: tokio::sync::mpsc::Receiver<ChannelMessage>,
    ar_tx: tokio::sync::mpsc::Sender<ChannelMessage>,
    atomic_register: Box<dyn AtomicRegister>,
    hmac_client_key: [u8; 32],
) {
    tokio::spawn(async move {
        let mut atomic_register = atomic_register;
        let mut client_cmd_fifo = Vec::new();
        let mut not_busy = true;
        loop {
            // get channel_message from the router
            let channel_message = match ar_rx.recv().await {
                Some(cmd) => cmd,
                None => {
                    break;
                }
            };

            match channel_message {
                // new message from router
                ChannelMessage::FromTcp((cmd, _is_ok, callback_channel_tx)) => {
                    match cmd {
                        RegisterCommand::Client(client_cmd) => {
                            // check if the atomic register is ready to accept new command
                            if not_busy {
                                let atomic_register_task_tx = ar_tx.clone();
                                serve_client_command(
                                    client_cmd,
                                    &mut *atomic_register,
                                    Box::new(move |operation_success| {
                                        // notify executor that the atomic register is ready to accept new command

                                        let callback_channel_tx = callback_channel_tx.expect("No callback channel provided for sending error message").clone();
                                        // \/ this is feature being awaited in atomic_register
                                        Box::pin(async move {
                                            atomic_register_task_tx
                                                .send(ChannelMessage::AtomRegisterFinished)
                                                .await
                                                .unwrap();

                                            let response = success_callback_serialize_response(
                                                operation_success,
                                                &hmac_client_key,
                                            )
                                            .await;
                                            callback_channel_tx.send(response).await.unwrap();
                                        })
                                    }),
                                )
                                .await;

                                not_busy = false;
                            } else {
                                // atomic register is not ready to accept new command, we are going to queue it
                                client_cmd_fifo.push((client_cmd, callback_channel_tx));
                            }
                        }

                        // we can always process system commands
                        RegisterCommand::System(system_cmd) => {
                            atomic_register.system_command(system_cmd).await;
                        }
                    }
                }

                // Atomic register finished processing the client command
                ChannelMessage::AtomRegisterFinished => {
                    // check if there are any commands in the fifo
                    if !client_cmd_fifo.is_empty() {
                        // get cmd from fifo
                        let (client_cmd, callback_channel_tx) = client_cmd_fifo.remove(0);
                        let atomic_register_task_tx = ar_tx.clone();

                        // serve the client command
                        serve_client_command(
                            client_cmd,
                            &mut *atomic_register,
                            Box::new(move |operation_success| {
                                // notify executor that the atomic register is ready to accept new command

                                let callback_channel_tx = callback_channel_tx
                                    .expect(
                                        "No callback channel provided for sending error message",
                                    )
                                    .clone();
                                // \/ this is feature being awaited in atomic_register
                                Box::pin(async move {
                                    atomic_register_task_tx
                                        .send(ChannelMessage::AtomRegisterFinished)
                                        .await
                                        .unwrap();
                                    let response = success_callback_serialize_response(
                                        operation_success,
                                        &hmac_client_key,
                                    )
                                    .await;
                                    callback_channel_tx.send(response).await.unwrap();
                                })
                            }),
                        )
                        .await;
                    } else {
                        // if there are no commands in the fifo, we can process new client commands
                        not_busy = true;
                    }
                }
            }
        }
    });
}

async fn serve_client_command(
    client_cmd: ClientRegisterCommand,
    atomic_register: &mut dyn AtomicRegister,
    success_callback: Box<
        dyn FnOnce(OperationSuccess) -> Pin<Box<dyn Future<Output = ()> + std::marker::Send>>
            + std::marker::Send
            + Sync,
    >,
) {
    atomic_register
        .client_command(client_cmd, success_callback)
        .await;
}

async fn success_callback_serialize_response(
    operation_success: OperationSuccess,
    client_hmac_key: &[u8; 32],
) -> Vec<u8> {
    let mut message = Vec::new();
    let mut hmac = Hmac::<Sha256>::new_from_slice(client_hmac_key).unwrap();

    // add the magic number to the message
    message.extend_from_slice(&MAGIC_NUMBER);

    // add 16 bits of 77s for padding
    message.extend_from_slice(&[77; 2]);

    // add Ok status code
    message.push(StatusCode::Ok as u8); // we assume success

    match operation_success.op_return {
        OperationReturn::Read(read_return) => {
            // add msg type
            message.push(64 + 1);

            // add the request number in BIG ENDIAN
            message.extend_from_slice(&operation_success.request_identifier.to_be_bytes());

            // add the sector data
            message.extend_from_slice(&read_return.read_data.0);
        }
        OperationReturn::Write => {
            // add msg type
            message.push(64 + 2);

            // add the request number in BIG ENDIAN
            message.extend_from_slice(&operation_success.request_identifier.to_be_bytes());

            // no content to add
        }
    }

    // sign the message
    hmac.update(&message);
    let tag = hmac.finalize().into_bytes();
    message.extend_from_slice(&tag);

    message
}

async fn fail_serialize_response(
    status_code: StatusCode,
    msg_type_1_or_2: u8,
    request_number: u64,
    client_hmac_key: &[u8; 32],
) -> Vec<u8> {
    let mut message = Vec::new();
    let mut hmac = Hmac::<Sha256>::new_from_slice(client_hmac_key).unwrap();

    // add the magic number to the message
    message.extend_from_slice(&MAGIC_NUMBER);

    // add 16 bits of 77s for padding
    message.extend_from_slice(&[77; 2]);

    // add status code
    message.push(status_code as u8);

    // add msg type
    message.push(64 + msg_type_1_or_2);

    // add the request number in BIG ENDIAN
    message.extend_from_slice(&request_number.to_be_bytes());

    // sign the message
    hmac.update(&message);
    let tag = hmac.finalize().into_bytes();
    message.extend_from_slice(&tag);

    message
}

async fn is_command_valid_handle_invalid(
    cmd: RegisterCommand,
    is_hmac_ok: bool,
    callback_channel_tx: Option<tokio::sync::mpsc::Sender<Vec<u8>>>,
    client_hmac_key: &[u8; 32],
    max_sector_idx: u64,
) -> bool {
    // wrong HMAC
    match cmd {
        RegisterCommand::Client(ClientRegisterCommand { header, content }) => {
            if !is_hmac_ok {
                let response = fail_serialize_response(
                    StatusCode::AuthFailure,
                    match content {
                        ClientRegisterCommandContent::Read => 1,
                        ClientRegisterCommandContent::Write { .. } => 2,
                    },
                    header.request_identifier,
                    client_hmac_key,
                )
                .await;
                callback_channel_tx
                    .expect("No callback channel provided for sending error message")
                    .send(response)
                    .await
                    .unwrap();
                return false;
            }
            // invalid sector index
            if header.sector_idx >= max_sector_idx {
                let response = fail_serialize_response(
                    StatusCode::InvalidSectorIndex,
                    match content {
                        ClientRegisterCommandContent::Read => 1,
                        ClientRegisterCommandContent::Write { .. } => 2,
                    },
                    header.request_identifier,
                    client_hmac_key,
                )
                .await;
                callback_channel_tx
                    .expect("No callback channel provided for sending error message")
                    .send(response)
                    .await
                    .unwrap();
                return false;
            }
        }
        RegisterCommand::System(SystemRegisterCommand { header, .. }) => {
            if !is_hmac_ok {
                // just ignore invalid system command
                return false;
            }
            // invalid sector index
            if header.sector_idx >= max_sector_idx {
                // just ignore invalid system command
                return false;
            }
        }
    }
    true
}

/// checks if there is system Ack in the TCP stream,
/// if there is it notifies the RegisterClient and consumes the message from the stream
/// if there isn't it doesn't consume any bytes
async fn system_ack_deserialize(
    stream: &mut TcpStream, // maybe there is a need to specify it as a TCP stream,
    system_hmac_key: &[u8; 64],
) -> Result<SystemAck, std::io::Error> {
    // read and consume first line
    let mut first_line = [0; 8];
    match stream.read_exact(&mut first_line).await {
        Ok(_) => {}
        Err(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "Problem with reading from stream",
            ));
        }
    }
    let msg_type = first_line[7];

    let process_identifier = first_line[6];

    // read and consume 16 bytes of msg ident
    let mut msg_ident = [0; 16];
    match stream.read_exact(&mut msg_ident).await {
        Ok(_) => {}
        Err(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "Problem with reading from stream",
            ));
        }
    } // if read fails, we just ignore the message

    let mut hmac_tag = [0; 32];
    match stream.read_exact(&mut hmac_tag).await {
        Ok(_) => {}
        Err(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "Problem with reading from stream",
            ));
        }
    } // if read fails, we just ignore the message

    let msg_type = msg_type - 64;
    let system_ack = SystemAck {
        process_identifier,
        msg_type,
        msg_ident: Uuid::from_slice(&msg_ident).unwrap(),
    };

    // check if the HMAC is valid
    let mut hmac = Hmac::<Sha256>::new_from_slice(system_hmac_key).unwrap();
    hmac.update(&first_line);
    hmac.update(&msg_ident);
    let tag = hmac.finalize().into_bytes();
    if tag.as_slice() != hmac_tag {
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Invalid HMAC",
        ))
    } else {
        Ok(system_ack)
    }
}

async fn make_and_serialize_system_ack(
    cmd: &SystemRegisterCommand,
    my_process_identifier: u8,
    system_hmac_key: &[u8; 64],
) -> Vec<u8> {
    let mut message = Vec::new();
    let mut hmac = Hmac::<Sha256>::new_from_slice(system_hmac_key).unwrap();

    // add the magic number to the message
    message.extend_from_slice(&MAGIC_NUMBER);

    // add 16 bits of 77s for padding
    message.extend_from_slice(&[77; 2]);

    // add process identifier
    message.push(my_process_identifier);

    // add msg type
    let msg_type = match cmd.content {
        SystemRegisterCommandContent::ReadProc => 64 + 3,
        SystemRegisterCommandContent::Value { .. } => 64 + 4,
        SystemRegisterCommandContent::WriteProc { .. } => 64 + 5,
        SystemRegisterCommandContent::Ack => 64 + 6,
    };

    message.push(msg_type);

    // add msg ident
    let msg_ident = cmd.header.msg_ident.as_u128();
    message.extend_from_slice(&msg_ident.to_be_bytes());

    // sign the message
    hmac.update(&message);
    let tag = hmac.finalize().into_bytes();
    message.extend_from_slice(&tag);
    message
}
pub mod atomic_register_public {
    use uuid::Uuid;

    use crate::{
        register_client_public, register_client_public::Broadcast,
        register_client_public::RegisterClient, ClientRegisterCommand,
        ClientRegisterCommandContent, OperationReturn, OperationSuccess, ReadReturn, SectorIdx,
        SectorVec, SectorsManager, SystemCommandHeader, SystemRegisterCommand,
        SystemRegisterCommandContent,
    };
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Arc;

    #[async_trait::async_trait]
    pub trait AtomicRegister: Send + Sync {
        /// Handle a client command. After the command is completed, we expect
        /// callback to be called. Note that completion of client command happens after
        /// delivery of multiple system commands to the register, as the algorithm specifies.
        ///
        /// This function corresponds to the handlers of Read and Write events in the
        /// (N,N)-AtomicRegister algorithm.
        async fn client_command(
            &mut self,
            cmd: ClientRegisterCommand,
            success_callback: Box<
                dyn FnOnce(OperationSuccess) -> Pin<Box<dyn Future<Output = ()> + Send>>
                    + Send
                    + Sync,
            >,
        );

        /// Handle a system command.
        ///
        /// This function corresponds to the handlers of READ_PROC, VALUE, WRITE_PROC
        /// and ACK messages in the (N,N)-AtomicRegister algorithm.
        async fn system_command(&mut self, cmd: SystemRegisterCommand);
    }

    pub struct AtomicRegisterStruct {
        timestamp: u64,           // to be stored
        write_rank: u8,           // to be stored
        value: Option<SectorVec>, // to be stored
        readlist: Vec<(u64, u8, SectorVec)>,
        acks: Vec<u8>,
        reading: bool,
        writing: bool,
        writeval: Option<SectorVec>,
        readval: Option<SectorVec>,
        write_phase: bool,
        op_id: u128,

        self_ident: u8,
        number_of_processes: u8,
        register_client: Arc<dyn RegisterClient>,
        sectors_manager: Arc<dyn SectorsManager>,
        sector_idx: SectorIdx,
        request_identifier: Option<u64>,
        success_callback: Option<
            Box<
                dyn FnOnce(OperationSuccess) -> Pin<Box<dyn Future<Output = ()> + Send>>
                    + Send
                    + Sync,
            >,
        >,
    }

    impl AtomicRegisterStruct {
        pub fn new(
            number_of_processes: u8,
            register_client: Arc<dyn RegisterClient>,
            sectors_manager: Arc<dyn SectorsManager>,
            sector_idx: SectorIdx,
            self_ident: u8,
        ) -> Self {
            AtomicRegisterStruct {
                timestamp: 0,
                write_rank: 0,
                value: None,
                readlist: Vec::new(),
                acks: Vec::new(),
                reading: false,
                writing: false,
                writeval: None,
                readval: None,
                write_phase: false,
                op_id: 0,

                self_ident,
                number_of_processes,
                register_client,
                sectors_manager,
                sector_idx,
                request_identifier: None,
                success_callback: None,
            }
        }

        fn generate_op_id(&mut self) -> u128 {
            // generate random Uuid
            let op_id = Uuid::new_v4();
            op_id.as_u128()
        }

        fn get_value(&self) -> SectorVec {
            match self.value {
                Some(ref val) => val.clone(),
                None => SectorVec(vec![0; 4096]),
            }
        }

        fn set_value(&mut self, value: SectorVec) {
            self.value = Some(value);
        }

        async fn store(&self) {
            // store timestamp, write_rank and value in the sectors_manager
            let sector = (self.get_value(), self.timestamp, self.write_rank);
            let sectors_manager = Arc::clone(&self.sectors_manager);
            let sector_idx = self.sector_idx;
            sectors_manager.write(sector_idx, &sector).await;
        }

        async fn retrive(&mut self) {
            // retrive timestamp, write_rank and value from the sectors_manager
            let data = self.sectors_manager.read_data(self.sector_idx).await;
            let metadata = self.sectors_manager.read_metadata(self.sector_idx).await;
            self.timestamp = metadata.0;
            self.write_rank = metadata.1;
            self.value = Some(data);
        }
    }

    #[async_trait::async_trait]
    impl AtomicRegister for AtomicRegisterStruct {
        async fn client_command(
            &mut self,
            cmd: ClientRegisterCommand,
            success_callback: Box<
                dyn FnOnce(OperationSuccess) -> Pin<Box<dyn Future<Output = ()> + Send>>
                    + Send
                    + Sync,
            >,
        ) {
            self.request_identifier = Some(cmd.header.request_identifier);
            self.success_callback = Some(success_callback);

            match cmd.content {
                ClientRegisterCommandContent::Read => {
                    // read operation
                    self.op_id = self.generate_op_id();
                    self.readlist = Vec::new();
                    self.acks = Vec::new();
                    self.reading = true;
                    self.register_client
                        .broadcast(Broadcast {
                            cmd: Arc::new(SystemRegisterCommand {
                                header: SystemCommandHeader {
                                    process_identifier: self.self_ident,
                                    msg_ident: Uuid::from_u128(self.op_id),
                                    sector_idx: self.sector_idx,
                                },
                                content: SystemRegisterCommandContent::ReadProc,
                            }),
                        })
                        .await;
                }
                ClientRegisterCommandContent::Write { data } => {
                    // write operation
                    self.op_id = self.generate_op_id();
                    self.writeval = Some(data);
                    self.acks = Vec::new();
                    self.readlist = Vec::new();
                    self.writing = true;
                    self.register_client
                        .broadcast(Broadcast {
                            cmd: Arc::new(SystemRegisterCommand {
                                header: SystemCommandHeader {
                                    process_identifier: self.self_ident,
                                    msg_ident: Uuid::from_u128(self.op_id),
                                    sector_idx: self.sector_idx,
                                },
                                content: SystemRegisterCommandContent::ReadProc,
                            }),
                        })
                        .await;
                }
            }
        }

        async fn system_command(&mut self, cmd: SystemRegisterCommand) {
            match cmd.content {
                SystemRegisterCommandContent::ReadProc => {
                    // send back the value
                    self.register_client
                        .send(register_client_public::Send {
                            cmd: Arc::new(SystemRegisterCommand {
                                header: SystemCommandHeader {
                                    process_identifier: self.self_ident,
                                    msg_ident: cmd.header.msg_ident,
                                    sector_idx: self.sector_idx,
                                },
                                content: SystemRegisterCommandContent::Value {
                                    timestamp: self.timestamp,
                                    write_rank: self.write_rank,
                                    sector_data: self.get_value(),
                                },
                            }),
                            target: cmd.header.process_identifier,
                        })
                        .await;
                }
                SystemRegisterCommandContent::Value {
                    timestamp,
                    write_rank,
                    sector_data,
                } => {
                    self.readlist.push((timestamp, write_rank, sector_data));

                    if self.readlist.len() > (self.number_of_processes / 2).into() {
                        let max_timestamp =
                            self.readlist.iter().map(|(ts, _, _)| *ts).max().unwrap();
                        let max_write_rank = self
                            .readlist
                            .iter()
                            .filter(|(ts, _, _)| *ts == max_timestamp)
                            .map(|(_, wr, _)| *wr)
                            .max()
                            .unwrap();
                        let max_val = self
                            .readlist
                            .iter()
                            .filter(|(ts, wr, _)| *ts == max_timestamp && *wr == max_write_rank)
                            .map(|(_, _, val)| val.clone())
                            .next()
                            .unwrap();
                        self.readval = Some(max_val.clone());

                        self.readlist.clear();
                        self.acks.clear();
                        self.write_phase = true;

                        if self.reading {
                            // READING
                            self.register_client
                                .broadcast(Broadcast {
                                    cmd: Arc::new(SystemRegisterCommand {
                                        header: SystemCommandHeader {
                                            process_identifier: self.self_ident,
                                            msg_ident: cmd.header.msg_ident,
                                            sector_idx: self.sector_idx,
                                        },
                                        content: SystemRegisterCommandContent::WriteProc {
                                            timestamp: max_timestamp,
                                            write_rank: max_write_rank,
                                            data_to_write: max_val,
                                        },
                                    }),
                                })
                                .await;
                        } else {
                            // WRITING
                            self.timestamp = max_timestamp + 1;
                            self.write_rank = self.self_ident;
                            let writeval = self.writeval.take().unwrap();
                            self.set_value(writeval.clone());
                            // store timestamp, write_rank and value in the sectors_manager
                            self.store().await;

                            self.register_client
                                .broadcast(Broadcast {
                                    cmd: Arc::new(SystemRegisterCommand {
                                        header: SystemCommandHeader {
                                            process_identifier: self.self_ident,
                                            msg_ident: cmd.header.msg_ident,
                                            sector_idx: self.sector_idx,
                                        },
                                        content: SystemRegisterCommandContent::WriteProc {
                                            timestamp: self.timestamp,
                                            write_rank: self.write_rank,
                                            data_to_write: writeval,
                                        },
                                    }),
                                })
                                .await;
                        }
                    }
                }
                SystemRegisterCommandContent::WriteProc {
                    timestamp,
                    write_rank,
                    data_to_write,
                } => {
                    if timestamp > self.timestamp
                        || (timestamp == self.timestamp && write_rank > self.write_rank)
                    {
                        self.timestamp = timestamp;
                        self.write_rank = write_rank;
                        self.set_value(data_to_write);
                        // store timestamp, write_rank and value in the sectors_manager
                        self.store().await;
                    }

                    // send ack
                    self.register_client
                        .send(register_client_public::Send {
                            cmd: Arc::new(SystemRegisterCommand {
                                header: SystemCommandHeader {
                                    process_identifier: self.self_ident,
                                    msg_ident: cmd.header.msg_ident,
                                    sector_idx: self.sector_idx,
                                },
                                content: SystemRegisterCommandContent::Ack,
                            }),
                            target: cmd.header.process_identifier,
                        })
                        .await;
                }
                SystemRegisterCommandContent::Ack => {
                    if cmd.header.msg_ident == Uuid::from_u128(self.op_id) {
                        self.acks.push(cmd.header.process_identifier);
                        if self.acks.len() > (self.number_of_processes / 2).into() {
                            self.acks.clear();
                            self.write_phase = false;

                            if self.reading {
                                // reading = TRUE
                                self.reading = false;

                                // call callback
                                let callback = self.success_callback.take().unwrap();
                                callback(OperationSuccess {
                                    request_identifier: self.request_identifier.unwrap(),
                                    op_return: OperationReturn::Read(ReadReturn {
                                        read_data: self.readval.take().unwrap(), // FIXME check if it doesn't panic on take
                                    }),
                                })
                                .await;
                            } else if self.writing {
                                // reading = FALSE
                                self.writing = false;

                                // call callback
                                let callback = self.success_callback.take().unwrap();
                                callback(OperationSuccess {
                                    request_identifier: self.request_identifier.unwrap(),
                                    op_return: OperationReturn::Write,
                                })
                                .await;
                            }
                        }
                    }
                }
            }
        }
    }

    /// Idents are numbered starting at 1 (up to the number of processes in the system).
    /// Communication with other processes of the system is to be done by register_client.
    /// And sectors must be stored in the sectors_manager instance.
    ///
    /// This function corresponds to the handlers of Init and Recovery events in the
    /// (N,N)-AtomicRegister algorithm.
    pub async fn build_atomic_register(
        self_ident: u8,
        sector_idx: SectorIdx,
        register_client: Arc<dyn RegisterClient>,
        sectors_manager: Arc<dyn SectorsManager>,
        processes_count: u8,
    ) -> Box<dyn AtomicRegister> {
        // unimplemented!()
        let mut atomic_register = AtomicRegisterStruct::new(
            processes_count,
            register_client,
            sectors_manager,
            sector_idx,
            self_ident,
        );
        atomic_register.retrive().await;
        Box::new(atomic_register)
    }
}

pub mod sectors_manager_public {
    use serde::{Deserialize, Serialize};
    use sha2::{Digest, Sha256};
    use tokio::io::AsyncWriteExt;

    use crate::{SectorIdx, SectorVec};
    use std::path::PathBuf;
    use std::sync::Arc;

    #[async_trait::async_trait]
    pub trait SectorsManager: Send + Sync {
        /// Returns 4096 bytes of sector data by index.
        async fn read_data(&self, idx: SectorIdx) -> SectorVec;

        /// Returns timestamp and write rank of the process which has saved this data.
        /// Timestamps and ranks are relevant for atomic register algorithm, and are described
        /// there.
        async fn read_metadata(&self, idx: SectorIdx) -> (u64, u8);

        /// Writes a new data, along with timestamp and write rank to some sector.
        async fn write(&self, idx: SectorIdx, sector: &(SectorVec, u64, u8));
    }

    pub struct SectorsManagerStruct {
        base_path: PathBuf,
    }

    #[derive(Serialize, Deserialize)]
    struct FileContent {
        timestamp: u64,
        write_rank: u8,
        data: Vec<u8>,
    }

    #[derive(Serialize, Deserialize)]
    struct FileWithHash {
        content: FileContent,
        hash: Vec<u8>,
    }

    #[async_trait::async_trait]
    impl SectorsManager for SectorsManagerStruct {
        async fn read_data(&self, idx: SectorIdx) -> SectorVec {
            let file_path = self.base_path.join(format!("sector_{}", idx));
            let file_path_ok = file_path.with_extension("ok");
            let file_path_tmp = file_path.with_extension("tmp");

            // check if the file exists
            if file_path_ok.exists() && !file_path_tmp.exists() {
                let file = tokio::fs::read(&file_path_ok).await.unwrap();
                let data = bincode::deserialize::<FileContent>(&file).unwrap();
                return SectorVec(data.data);
            } else if file_path_tmp.exists() {
                // read the file
                let file = tokio::fs::read(&file_path_tmp).await.unwrap();
                let file_with_hash = bincode::deserialize::<FileWithHash>(&file).unwrap();
                let hash = Sha256::digest(bincode::serialize(&file_with_hash.content).unwrap());
                if hash.as_slice() == file_with_hash.hash.as_slice() {
                    return SectorVec(file_with_hash.content.data);
                } else {
                    // return 4096 bytes of zeros
                    return SectorVec(vec![0; 4096]);
                }
            } else {
                // return 4096 bytes of zeros
                return SectorVec(vec![0; 4096]);
            }
        }

        async fn read_metadata(&self, idx: SectorIdx) -> (u64, u8) {
            let file_path = self.base_path.join(format!("sector_{}", idx));
            let file_path_ok = file_path.with_extension("ok");
            let file_path_tmp = file_path.with_extension("tmp");

            // check if the file exists
            if file_path_ok.exists() && !file_path_tmp.exists() {
                let file = tokio::fs::read(&file_path_ok).await.unwrap();
                let data = bincode::deserialize::<FileContent>(&file).unwrap();
                return (data.timestamp, data.write_rank);
            } else if file_path_tmp.exists() {
                // read the file
                let file = tokio::fs::read(&file_path_tmp).await.unwrap();
                let file_with_hash = bincode::deserialize::<FileWithHash>(&file).unwrap();
                let hash = Sha256::digest(bincode::serialize(&file_with_hash.content).unwrap());
                if hash.as_slice() == file_with_hash.hash.as_slice() {
                    return (
                        file_with_hash.content.timestamp,
                        file_with_hash.content.write_rank,
                    );
                } else {
                    // return 0 timestamp and 0 write rank
                    return (0, 0);
                }
            } else {
                // return 0 timestamp and 0 write rank
                return (0, 0);
            }
        }

        async fn write(&self, idx: SectorIdx, sector: &(SectorVec, u64, u8)) {
            let file_content = FileContent {
                timestamp: sector.1,
                write_rank: sector.2,
                data: sector.0.clone().0,
            };

            let file_path = self.base_path.join(format!("sector_{}", idx));
            // add tmp extension to the file
            let tmp_file_path = file_path.with_extension("tmp");

            // create temp file with hash and save it
            let serialized_file_content = bincode::serialize(&file_content).unwrap();
            let hash = Sha256::digest(&serialized_file_content);
            let file_plus_hash = FileWithHash {
                content: file_content,
                hash: hash.to_vec(),
            };
            let mut tmp_file = tokio::fs::File::create(&tmp_file_path).await.unwrap();
            tmp_file
                .write_all(&bincode::serialize(&file_plus_hash).unwrap())
                .await
                .unwrap();

            // sync in POSIX
            tmp_file.sync_all().await.unwrap();

            // sync the directory
            tokio::fs::File::open(&self.base_path)
                .await
                .unwrap()
                .sync_all()
                .await
                .unwrap();

            // write the actual file
            // add the ok extension to the file
            let dst_file_path = file_path.with_extension("ok");
            let mut dst_file = tokio::fs::File::create(&dst_file_path).await.unwrap();
            dst_file.write_all(&serialized_file_content).await.unwrap();
            // call POSIX fsync to ensure the data is written to disk
            dst_file.sync_all().await.unwrap();

            // sync the directory to ensure the file is visible
            tokio::fs::File::open(&self.base_path)
                .await
                .unwrap()
                .sync_all()
                .await
                .unwrap();

            // remove the tmp file
            tokio::fs::remove_file(&tmp_file_path).await.unwrap();

            // sync the directory to ensure there is no tmp file
            tokio::fs::File::open(&self.base_path)
                .await
                .unwrap()
                .sync_all()
                .await
                .unwrap();
        }
    }

    /// Path parameter points to a directory to which this method has exclusive access.
    pub async fn build_sectors_manager(path: PathBuf) -> Arc<dyn SectorsManager> {
        let sectors_manager = SectorsManagerStruct { base_path: path };
        Arc::new(sectors_manager)
    }
}

pub mod transfer_public {
    use crate::{
        ClientCommandHeader, ClientRegisterCommand, ClientRegisterCommandContent, RegisterCommand,
        SectorVec, SystemCommandHeader, SystemRegisterCommand, SystemRegisterCommandContent,
        MAGIC_NUMBER,
    };
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    use std::io::Error;
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
    use uuid::Uuid;

    async fn deserialize_system_command_content(
        msg_type: u8,
        data: &mut (dyn AsyncRead + Send + Unpin),
        mac: &mut Hmac<Sha256>,
    ) -> Result<SystemRegisterCommandContent, Error> {
        if msg_type == 3 {
            // READ_PROC
            Ok(SystemRegisterCommandContent::ReadProc)
        } else if msg_type == 4 {
            // VALUE
            // read timestamp
            let mut timestamp = [0; 8];
            data.read_exact(&mut timestamp).await?;
            let timestamp = u64::from_be_bytes(timestamp);

            // read 56 bits of padding
            let mut padding = [0; 7];
            data.read_exact(&mut padding).await?;

            // read Value wr
            let mut value_wr = [0; 1];
            data.read_exact(&mut value_wr).await?;
            let value_wr = value_wr[0];

            // read sector data
            let mut sector_data = [0; 4096];
            data.read_exact(&mut sector_data).await?;

            // update the mac
            mac.update(&timestamp.to_be_bytes());
            mac.update(&padding);
            mac.update(&[value_wr]);
            mac.update(&sector_data);

            let value = SystemRegisterCommandContent::Value {
                timestamp,
                write_rank: value_wr,
                sector_data: SectorVec(sector_data.to_vec()),
            };

            Ok(value)
        } else if msg_type == 5 {
            // WRITE_PROC
            // read timestamp
            let mut timestamp = [0; 8];
            data.read_exact(&mut timestamp).await?;
            let timestamp = u64::from_be_bytes(timestamp);

            // read 56 bits of padding
            let mut padding = [0; 7];
            data.read_exact(&mut padding).await?;

            // read Value wr
            let mut value_wr = [0; 1];
            data.read_exact(&mut value_wr).await?;
            let value_wr = value_wr[0];

            // read sector data
            let mut sector_data = [0; 4096];
            data.read_exact(&mut sector_data).await?;

            // update the mac
            mac.update(&timestamp.to_be_bytes());
            mac.update(&padding);
            mac.update(&[value_wr]);
            mac.update(&sector_data);

            let value = SystemRegisterCommandContent::WriteProc {
                timestamp,
                write_rank: value_wr,
                data_to_write: SectorVec(sector_data.to_vec()),
            };

            Ok(value)
        } else if msg_type == 6 {
            // ACK
            Ok(SystemRegisterCommandContent::Ack)
        } else {
            return Err(Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid message type",
            ));
        }
    }

    pub async fn deserialize_register_command(
        data: &mut (dyn AsyncRead + Send + Unpin),
        hmac_system_key: &[u8; 64],
        hmac_client_key: &[u8; 32],
    ) -> Result<(RegisterCommand, bool), Error> {
        //reading till Magic number
        let mut magic_number = [0; 4];
        let mut message_type ;
        let mut padding = [0; 3];
        loop{
            data.read_exact(&mut magic_number).await?;
            while magic_number != MAGIC_NUMBER {
                magic_number[0] = magic_number[1];
                magic_number[1] = magic_number[2];
                magic_number[2] = magic_number[3];
                data.read_exact(&mut magic_number[3..4]).await?;
            }
            
            // read the padding
            data.read_exact(&mut padding).await?;
            
            // read the message type
            let mut buf1 = [0 as u8; 1];
            data.read_exact(&mut buf1).await?;
            message_type = buf1[0];
            if message_type <= 6 {
                break;
            }
        }
        // Client vs System command
        if message_type <= 2 {
            // client command
            // read the request number
            let mut request_number = [0; 8];
            data.read_exact(&mut request_number).await?;
            let request_number = u64::from_be_bytes(request_number);

            // read the sector index
            let mut sector_index = [0; 8];
            data.read_exact(&mut sector_index).await?;
            let sector_index = u64::from_be_bytes(sector_index);

            // read the content
            let mut command_content = [0; 4096];
            if message_type == 1 { // READ command
                 // no content for READ command
            } else if message_type == 2 {
                // WRITE command
                // read command content
                data.read_exact(&mut command_content).await?;
            } else {
                // TODO remove this
                return Err(Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Invalid message type",
                ));
            }

            // read the tag
            let mut tag = [0; 32];
            data.read_exact(&mut tag).await?;

            // verify the tag
            let mut mac = Hmac::<Sha256>::new_from_slice(hmac_client_key).unwrap();
            mac.update(&magic_number);
            mac.update(&padding);
            mac.update(&[message_type]);
            mac.update(&request_number.to_be_bytes());
            mac.update(&sector_index.to_be_bytes());
            if message_type == 2 {
                mac.update(&command_content);
            }

            let client_command = RegisterCommand::Client(ClientRegisterCommand {
                header: ClientCommandHeader {
                    request_identifier: request_number,
                    sector_idx: sector_index,
                },
                content: match message_type {
                    1 => ClientRegisterCommandContent::Read,
                    2 => ClientRegisterCommandContent::Write {
                        data: SectorVec(command_content.to_vec()),
                    },
                    _ => unreachable!(),
                },
            });

            if mac.verify_slice(&tag).is_ok() {
                Ok((client_command, true))
            } else {
                Ok((client_command, false))
            }
        } else if message_type > 2 && message_type <= 6 {
            // system command
            // create a new mac
            let mut mac = Hmac::<Sha256>::new_from_slice(hmac_system_key).unwrap();

            let process_rank = padding[2];

            // read UUID
            let mut uuid = [0; 16];
            data.read_exact(&mut uuid).await?;

            // read the sector index
            let mut sector_index = [0; 8];
            data.read_exact(&mut sector_index).await?;
            let sector_index = u64::from_be_bytes(sector_index);

            // update the mac
            mac.update(&magic_number);
            mac.update(&padding); // includes the process rank
            mac.update(&[message_type]);
            mac.update(&uuid);
            mac.update(&sector_index.to_be_bytes());

            // deserialize the system command content
            let system_command_content =
                deserialize_system_command_content(message_type, data, &mut mac).await?;

            // read the tag
            let mut tag = [0; 32];
            data.read_exact(&mut tag).await?;

            let system_command = RegisterCommand::System(SystemRegisterCommand {
                header: SystemCommandHeader {
                    process_identifier: process_rank,
                    msg_ident: Uuid::from_bytes(uuid),
                    sector_idx: sector_index,
                },
                content: system_command_content,
            });

            if mac.verify_slice(&tag).is_ok() {
                return Ok((system_command, true));
            } else {
                return Ok((system_command, false));
            }
        } else {
            return Err(Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid message type",
            ));
        }
    }

    async fn serialize_system_command_content(
        content: &SystemRegisterCommandContent,
        message: &mut Vec<u8>,
    ) -> Result<(), Error> {
        match content {
            SystemRegisterCommandContent::ReadProc => {
                // no content to add
            }
            SystemRegisterCommandContent::Value {
                timestamp,
                write_rank,
                sector_data,
            } => {
                // add the timestamp in BIG ENDIAN
                message.extend_from_slice(&timestamp.to_be_bytes());
                // add 56 bits of padding 77
                message.extend_from_slice(&[77; 7]);
                // add the write rank
                message.push(*write_rank);
                // add the sector data
                message.extend_from_slice(&sector_data.0);
            }
            SystemRegisterCommandContent::WriteProc {
                timestamp,
                write_rank,
                data_to_write,
            } => {
                // add the timestamp in BIG ENDIAN
                message.extend_from_slice(&timestamp.to_be_bytes());
                // add 56 bits of padding
                message.extend_from_slice(&[0; 7]);
                // add the write rank
                message.push(*write_rank);
                // add the sector data
                message.extend_from_slice(&data_to_write.0);
            }
            SystemRegisterCommandContent::Ack => {
                // no content to add
            }
        }
        Ok(())
    }
    pub async fn serialize_register_command(
        cmd: &RegisterCommand,
        writer: &mut (dyn AsyncWrite + Send + Unpin),
        hmac_key: &[u8],
    ) -> Result<(), Error> {
        match cmd {
            RegisterCommand::Client(client_cmd) => {
                let header = client_cmd.header;

                let mut message = Vec::new();
                // add the magic number to the message
                message.extend_from_slice(&MAGIC_NUMBER);

                // add 24 bits of 77s for padding
                message.extend_from_slice(&[77; 3]);

                // add message type
                message.extend_from_slice(match client_cmd.content {
                    ClientRegisterCommandContent::Read => &[1],
                    _ => &[2],
                });

                // add the request number in BIG ENDIAN
                message.extend_from_slice(&header.request_identifier.to_be_bytes());
                // add the sector index in BIG ENDIAN
                message.extend_from_slice(&header.sector_idx.to_be_bytes());
                // add command content
                match &client_cmd.content {
                    ClientRegisterCommandContent::Read => {
                        // no content to add
                    }
                    ClientRegisterCommandContent::Write { data } => {
                        // add the write command
                        message.extend_from_slice(&data.0);
                    }
                }

                // sign the message
                // Initialize a new MAC instance from the secret key:
                let mut mac = Hmac::<Sha256>::new_from_slice(hmac_key).unwrap();
                // Calculate MAC for the data (one can provide it in multiple portions):
                mac.update(message.as_slice());
                // Finalize the computations of MAC and obtain the resulting tag:
                let tag = mac.finalize().into_bytes();
                // add the tag to the message
                message.extend_from_slice(&tag);

                // write the message to the writer
                writer.write_all(&message).await?;
                // flush the writer
                writer.flush().await?;
                Ok(())
            }
            RegisterCommand::System(system_cmd) => {
                let header = system_cmd.header;

                let mut message = Vec::new();

                // add the magic number to the message
                message.extend_from_slice(&MAGIC_NUMBER);

                // add 16 bits of 77s for padding
                message.extend_from_slice(&[77; 2]);

                // add process rank
                message.push(header.process_identifier);

                // add msg type
                message.push(match &system_cmd.content {
                    SystemRegisterCommandContent::ReadProc => 3,
                    SystemRegisterCommandContent::Value { .. } => 4,
                    SystemRegisterCommandContent::WriteProc { .. } => 5,
                    SystemRegisterCommandContent::Ack => 6,
                });

                // add UUID in BIG ENDIAN
                message.extend_from_slice(header.msg_ident.as_bytes());

                // add sector index in BIG ENDIAN
                message.extend_from_slice(&header.sector_idx.to_be_bytes());

                // serialize the system command content
                serialize_system_command_content(&system_cmd.content, &mut message).await?;

                // sign the message
                // Initialize a new MAC instance from the secret key:
                let mut mac = Hmac::<Sha256>::new_from_slice(hmac_key).unwrap();
                // Calculate MAC for the data (one can provide it in multiple portions):
                mac.update(message.as_slice());
                // Finalize the computations of MAC and obtain the resulting tag:
                let tag = mac.finalize().into_bytes();
                // add the tag to the message
                message.extend_from_slice(&tag);

                // write the message to the writer
                writer.write_all(&message).await?;
                // flush the writer
                writer.flush().await?;

                Ok(())
            }
        }
    }
}

pub mod register_client_public {
    use tokio::{io::AsyncWriteExt, sync::Mutex};
    use uuid::Uuid;

    use crate::{
        system_ack_deserialize, RegisterCommand, ShortcutChannel, SystemAck, SystemRegisterCommand,
        SystemRegisterCommandContent,
    };
    use std::{collections::HashMap, sync::Arc};

    #[async_trait::async_trait]
    /// We do not need any public implementation of this trait. It is there for use
    /// in AtomicRegister. In our opinion it is a safe bet to say some structure of
    /// this kind must appear in your solution.
    pub trait RegisterClient: core::marker::Send + core::marker::Sync {
        /// Sends a system message to a single process.
        async fn send(&self, msg: Send);

        /// Broadcasts a system message to all processes in the system, including self.
        async fn broadcast(&self, msg: Broadcast);
    }

    pub struct Broadcast {
        pub cmd: Arc<SystemRegisterCommand>,
    }

    pub struct Send {
        pub cmd: Arc<SystemRegisterCommand>,
        /// Identifier of the target process. Those start at 1.
        pub target: u8,
    }

    pub struct RegisterClientStruct {
        processes_connections: Arc<HashMap<usize, Mutex<Option<tokio::net::TcpStream>>>>,
        hmac_key: [u8; 64],
        processes_number: u8,
        self_ident: u8,
        shortcut_tx: ShortcutChannel, // shortcut channel for sending messages within the same ATDD process
        active_sender_tasks_aborters:
            Arc<Mutex<HashMap<(u8, u8, Uuid), tokio::sync::mpsc::Sender<()>>>>,
    } // (proces rank of a receiving process, msg type (<=6), msg UUID)

    impl RegisterClientStruct {
        pub async fn new(
            tcp_locations: Vec<(String, u16)>,
            system_hmac_key: [u8; 64],
            self_ident: u8,
            shortcut_tx: ShortcutChannel,
        ) -> Self {
            let mut hash_map = HashMap::new();
            // populate the hashmap with None values
            for i in 1..=tcp_locations.len() {
                hash_map.insert(i, Mutex::new(None));
            }

            // connect to all other ATDD processes
            let processes_connections = Arc::new(hash_map);
            let mut process_id = 1;
            for (ip, port) in tcp_locations {
                // skip connecting to self
                if process_id == self_ident as usize {
                    process_id += 1;
                    continue;
                }

                let processes_connections_clone = Arc::clone(&processes_connections);
                tokio::spawn(async move {
                    let mut interval =
                        tokio::time::interval(tokio::time::Duration::from_millis(500));
                    interval.tick().await;
                    loop {
                        {
                            let slot = processes_connections_clone.get(&process_id).unwrap();
                            let mut slot = slot.lock().await;
                            if slot.is_none() {
                                match tokio::net::TcpStream::connect(format!("{}:{}", ip, port))
                                    .await
                                {
                                    Ok(stream) => {
                                        *slot = Some(stream);
                                        if slot.is_some() {
                                        }
                                        // break;
                                    }
                                    Err(_) => {
                                        // ignore the error
                                    }
                                };
                            }
                        }
                        // we don't want to break here, as process might die and ressurect
                        interval.tick().await;
                    }
                });
                process_id += 1;
            }
            // wait some time for the connections to be established
            tokio::time::sleep(tokio::time::Duration::from_millis(20)).await;

            let active_sender_tasks_aborters = Arc::new(Mutex::new(HashMap::new()));
            let active_sender_tasks_aborters_clone = Arc::clone(&active_sender_tasks_aborters);

            RegisterClientStruct {
                processes_connections,
                hmac_key: system_hmac_key,
                processes_number: process_id as u8 - 1,
                self_ident,
                shortcut_tx,
                active_sender_tasks_aborters: active_sender_tasks_aborters_clone,
            }
        }

        fn spawn_sending_task(
            &self,
            my_map: Arc<HashMap<usize, Mutex<Option<tokio::net::TcpStream>>>>,
            msg: Send,
            msg_uuid: Uuid,
            system_hmac_key: [u8; 64],
            my_active_sender_tasks_aborters: Arc<
                Mutex<HashMap<(u8, u8, Uuid), tokio::sync::mpsc::Sender<()>>>,
            >,
            mut rx: tokio::sync::mpsc::Receiver<()>,
        ) {
            // spawn the sender task
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(500));
                interval.tick().await;
                loop {
                    let target = msg.target as usize;

                    // send the message
                    // let stream = my_map.get(&target).expect("No stream found");
                    // get the stream
                    let stream_slot_mutex = my_map.get(&target).expect("Wrong target");
                    let mut stream_slot = stream_slot_mutex.lock().await;
                    let stream = match stream_slot.as_mut() {
                        Some(stream) => stream,
                        None => {
                            interval.tick().await;
                            continue;
                        }
                    };

                    let mut buffer = Vec::new();
                    let register_cmd = RegisterCommand::System(SystemRegisterCommand {
                        header: msg.cmd.header,
                        content: msg.cmd.content.clone(),
                    });
                    crate::transfer_public::serialize_register_command(
                        &register_cmd,
                        &mut buffer,
                        &system_hmac_key,
                    )
                    .await
                    .unwrap();
                    match stream.write_all(&buffer).await {
                        Ok(_) => {
                        }
                        Err(_) => {
                            // remove the stream from the hashmap
                            *stream_slot = None; // hopefully this will trigger the reconnection
                            interval.tick().await;
                            continue;
                        }
                    }
                    // wait for the ack or timeout
                    tokio::select! {
                        _ = rx.recv() => {
                            break;
                        }
                        _ = interval.tick() => {
                         // do nothing
                        }
                        result = system_ack_deserialize(stream, &system_hmac_key) => {
                            match result {
                                Ok(SystemAck { msg_ident, process_identifier, msg_type}) => {

                                    // send the ack to right task
                                    let key = (process_identifier, msg_type, msg_ident);
                                    let mut my_active_sender_tasks_aborters = my_active_sender_tasks_aborters.lock().await;
                                    let sender: tokio::sync::mpsc::Sender<()> = my_active_sender_tasks_aborters.remove(&key).expect("No sender found");

                                    // we want to remove this task from the active_sender_tasks_aborters hashmap so we can't place this
                                    // line before the previous one
                                    if msg_ident == msg_uuid && process_identifier == msg.target{
                                        break;
                                    }

                                    sender.send(()).await.expect("Failed to send the ack to the sender task");

                                }
                                // connection aborted
                                Err(e) => {
                                    match e.kind() {
                                        std::io::ErrorKind::ConnectionAborted => {
                                            // remove the stream from the hashmap
                                            *stream_slot = None; // hopefully this will trigger the reconnection
                                            interval.tick().await;
                                        }
                                        _ => {
                                            // do nothing
                                        }
                                    }
                                }
                            };
                        }
                    }
                }
            });
        }
    }

    #[async_trait::async_trait]
    impl RegisterClient for RegisterClientStruct {
        async fn send(&self, msg: Send) {
            if self.self_ident == msg.target {
                // send the message to the shortcut channel
                self.shortcut_tx
                    .send((
                        RegisterCommand::System(SystemRegisterCommand {
                            header: msg.cmd.header,
                            content: msg.cmd.content.clone(),
                        }),
                        true,
                        None,
                    ))
                    .await
                    .expect("Failed to send the message to the shortcut channel");
                return;
            } else {
                // create a channel to stop the sending task
                let (tx, rx) = tokio::sync::mpsc::channel::<()>(1);

                // create a key for the active_sender_tasks_aborters hashmap
                let msg_type = match msg.cmd.content {
                    SystemRegisterCommandContent::ReadProc => 3,
                    SystemRegisterCommandContent::Value { .. } => 4,
                    SystemRegisterCommandContent::WriteProc { .. } => 5,
                    SystemRegisterCommandContent::Ack => 6,
                };
                let msg_uuid = msg.cmd.header.msg_ident;
                let key = (msg.target, msg_type, msg_uuid); // key to the active_sender_tasks_aborters hashmap

                // add the sender to the active_sender_tasks_aborters
                let mut active_sender_tasks_aborters =
                    self.active_sender_tasks_aborters.lock().await;
                active_sender_tasks_aborters.insert(key, tx);

                // spawn the sending task
                self.spawn_sending_task(
                    self.processes_connections.clone(),
                    msg,
                    msg_uuid,
                    self.hmac_key,
                    self.active_sender_tasks_aborters.clone(),
                    rx,
                );
            }
        }

        async fn broadcast(&self, msg: Broadcast) {
            // call send for each process
            for i in 1..=self.processes_number {
                self.send(Send {
                    cmd: msg.cmd.clone(),
                    target: i,
                })
                .await;
            }
        }
    }
}
