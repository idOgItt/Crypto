// use futures::StreamExt;
// use messenger_protos::{
//     ClientRequest, ClientRequestType, CreateRoomRequest, EncryptionAlgorithm, JoinRoomRequest,
//     LeaveRoomRequest, MessengerServiceClient, PayloadType, SendKeyExchangeData, SendMessageRequest,
//     ServerEventType,
// };
// use num_bigint::{BigUint, ToBigUint};
// use rand::rngs::OsRng;
// use rustyline::DefaultEditor;
// use std::io::Write;
// use std::sync::Arc;
// use tokio::sync::mpsc;
// use tokio::sync::Mutex;
// use tokio_stream::wrappers::ReceiverStream;
// use tonic::Request;
// use uuid::Uuid;
// 
// use dh_crypto::{DhParameters, DiffieHellman, KeyExchangeAlgorithm, KeyPair};
// use loki97_crypto::Loki97Cipher;
// use symmetric_cipher::crypto::cipher_context::CipherContext;
// use symmetric_cipher::crypto::cipher_traits::SymmetricCipherWithRounds;
// use symmetric_cipher::crypto::cipher_types::{CipherMode, PaddingMode};
// use twofish_crypto::Twofish;
// 
// // State for the current client session
// #[derive(Clone, Default)]
// struct ClientSession {
//     client_id: String,
//     current_room_id: Option<String>,
//     encryption_algorithm: Option<EncryptionAlgorithm>,
//     dh_keypair: Option<KeyPair>,
//     shared_secret_key: Option<Vec<u8>>, // Derived symmetric key
// }
// 
// // RFC 3526 Group 14 (2048-bit MODP) parameters
// fn get_standard_dh_params() -> DhParameters {
//     let p_hex = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF";
//     let g_val: u64 = 2;
//     DhParameters {
//         p: BigUint::parse_bytes(p_hex.as_bytes(), 16).unwrap(),
//         g: g_val.to_biguint().unwrap(),
//     }
// }
// 
// // KDF (Key Derivation Function) - very simple example (HMAC-SHA256 would be better)
// // For a pet project, a simple hash might suffice if DH secret is large.
// // DO NOT USE THIS IN PRODUCTION.
// fn derive_key_from_shared_secret(secret: &BigUint, key_len_bytes: usize) -> Vec<u8> {
//     // Use a proper KDF like HKDF in a real application
//     let secret_bytes = secret.to_bytes_be();
//     // Simple truncation or hashing. Let's use first N bytes for simplicity.
//     // THIS IS NOT SECURE.
//     let mut key = secret_bytes;
//     key.resize(key_len_bytes, 0); // Pad with 0 or truncate
//     key
// }
// 
// #[tokio::main]
// async fn main() -> Result<(), Box<rustyline::error::ReadlineError>> {
//     env_logger::init();
//     let server_address = "http://0.0.0.0:50051";
//     let mut client = MessengerServiceClient::connect(server_address)
//         .await
//         .unwrap();
//     log::info!("Connected to server: {}", server_address);
// 
//     let session = Arc::new(Mutex::new(ClientSession {
//         client_id: Uuid::new_v4().to_string(),
//         ..Default::default()
//     }));
// 
//     let (client_tx, client_rx) = mpsc::channel(128); // client input -> server
//     let request_stream = ReceiverStream::new(client_rx);
// 
//     log::debug!("Attempting to establish chat_stream...");
//     let mut response_stream = match client.chat_stream(Request::new(request_stream)).await {
//         Ok(res) => {
//             log::debug!("chat_stream established successfully.");
//             res.into_inner()
//         }
//         Err(e) => {
//             log::error!("Failed to establish chat_stream: {}", e);
//             std::process::exit(0);
//         }
//     };
//     log::debug!("response_stream obtained.");
// 
//     // Task to handle incoming server messages
//     let client_tx_for_receiver = client_tx.clone();
//     let session_clone_for_receiver = Arc::clone(&session);
//     tokio::spawn(async move {
//         log::debug!("Receiver task started: waiting for server messages.");
//         while let Some(message_result) = response_stream.next().await {
//             match message_result {
//                 Ok(server_msg) => {
//                     log::debug!("Received from server: {:?}", server_msg);
//                     if let Some(event) = server_msg.event {
//                         let mut sess = session_clone_for_receiver.lock().await;
// 
//                         match event {
//                             ServerEventType::RoomInfo(info) => {
//                                 println!(
//                                     "[Room Info] ID: {}, Algo: {:?}, Participants: {:?}",
//                                     info.room_id, info.algorithm, info.participants
//                                 );
//                                 sess.current_room_id = Some(info.room_id.clone());
//                                 sess.encryption_algorithm =
//                                     messenger_protos::EncryptionAlgorithm::from_i32(info.algorithm);
// 
//                                 // If we are in a room and DH hasn't happened, and we are the second person, initiate.
//                                 // Or if we created and someone joined.
//                                 if info.participants.len() == 2 && sess.dh_keypair.is_none() {
//                                     println!("[System] Two participants in room. Initiating DH key exchange if not done.");
//                                     // This client will send its public key
//                                     let dh_params = get_standard_dh_params();
//                                     let dh_context = DiffieHellman::new(dh_params).unwrap();
//                                     let keypair = dh_context.generate_keypair(&mut OsRng);
//                                     sess.dh_keypair = Some(keypair.clone());
// 
//                                     let send_key_req = ClientRequest {
//                                         request_id: Uuid::new_v4().to_string(),
//                                         client_id: sess.client_id.clone(),
//                                         timestamp: chrono::Utc::now().timestamp_millis(),
//                                         request: Some(ClientRequestType::SendKeyExchange(
//                                             SendKeyExchangeData {
//                                                 room_id: info.room_id.clone(),
//                                                 public_key_dh: keypair.public_key.to_bytes_be(),
//                                             },
//                                         )),
//                                     };
// 
//                                     if let Err(e) = client_tx_for_receiver.send(send_key_req).await
//                                     {
//                                         log::error!("Receiver task: Failed to send DH key: {}", e);
//                                     } else {
//                                         println!("[System] My DH public key has been sent. Waiting for other party's key.");
//                                     }
//                                 }
//                             }
//                             ServerEventType::UserStatus(update) => {
//                                 println!(
//                                     "[User Update] In Room '{}': Client '{}' has {}",
//                                     update.room_id,
//                                     update.client_id,
//                                     if update.joined { "joined" } else { "left" }
//                                 );
//                                 if update.joined
//                                     && sess.current_room_id.as_ref() == Some(&update.room_id)
//                                     && sess.dh_keypair.is_none()
//                                     && update.client_id != sess.client_id
//                                 {
//                                     println!(
//                                         "[System] Other user joined. Sending my DH public key."
//                                     );
//                                     let dh_params = get_standard_dh_params();
//                                     let dh_context = DiffieHellman::new(dh_params).unwrap();
//                                     let keypair = dh_context.generate_keypair(&mut OsRng);
//                                     sess.dh_keypair = Some(keypair.clone());
// 
//                                     let room_id_for_key_exchange =
//                                         sess.current_room_id.as_ref().cloned().unwrap_or_default();
//                                     let send_key_req = ClientRequest {
//                                         request_id: Uuid::new_v4().to_string(),
//                                         client_id: sess.client_id.clone(),
//                                         timestamp: chrono::Utc::now().timestamp_millis(),
//                                         request: Some(ClientRequestType::SendKeyExchange(
//                                             SendKeyExchangeData {
//                                                 room_id: room_id_for_key_exchange, // Use current room ID
//                                                 public_key_dh: keypair.public_key.to_bytes_be(),
//                                             },
//                                         )),
//                                     };
//                                     // Actually send the request
//                                     if let Err(e) = client_tx_for_receiver.send(send_key_req).await
//                                     {
//                                         log::error!(
//                                             "Receiver task: Failed to send DH key on user join: {}",
//                                             e
//                                         );
//                                     } else {
//                                         println!("[System] My DH public key has been sent (other user joined). Waiting for other party's key.");
//                                     }
//                                 }
//                             }
//                             ServerEventType::ChatMessage(chat) => {
//                                 if let Some(key) = &sess.shared_secret_key {
//                                     let algo = sess
//                                         .encryption_algorithm
//                                         .unwrap_or(EncryptionAlgorithm::Loki97); // Default if somehow not set
//                                     let mut cipher_instance: Box<
//                                         dyn SymmetricCipherWithRounds + Send + Sync,
//                                     > = match algo {
//                                         EncryptionAlgorithm::Loki97 => {
//                                             Box::new(Loki97Cipher::new(&key))
//                                         }
//                                         EncryptionAlgorithm::Twofish => {
//                                             Box::new(Twofish::new(&key))
//                                         }
//                                         _ => {
//                                             println!(
//                                                 "[Error] Unsupported algorithm for decryption"
//                                             );
//                                             return;
//                                         }
//                                     };
//                                     cipher_instance
//                                         .set_key(&key)
//                                         .expect("Failed to set key for decryption");
// 
//                                     let initial_additional_params = cipher_instance
//                                         .export_round_keys()
//                                         .unwrap_or_else(|| key.clone());
// 
//                                     let ctx = CipherContext::new(
//                                         cipher_instance,
//                                         CipherMode::CBC,
//                                         PaddingMode::PKCS7,
//                                         Some(chat.iv.clone()),
//                                         initial_additional_params,
//                                     );
// 
//                                     let decrypted_output_buf = Vec::new();
//                                     match ctx
//                                         .decrypt(
//                                             symmetric_cipher::crypto::cipher_types::CipherInput::Bytes(
//                                                 chat.encrypted_payload.clone(),
//                                             ),
//                                             &mut symmetric_cipher::crypto::cipher_types::CipherOutput::Buffer(
//                                                 Box::new(decrypted_output_buf),
//                                             ),
//                                         )
//                                         .await
//                                     {
//                                         Ok(_) => {
//                                             // The decrypted data is now in the original buffer passed to CipherOutput::Buffer
//                                             // This needs adjustment in CipherContext or how it's used.
//                                             // Let's assume CipherOutput::Buffer holds the result.
//                                             // This is hacky, CipherContext should return the buffer or write to a mutable ref.
//                                             // For now, assume CipherOutput::Buffer's internal vec is updated.
//                                             // This is why the demo had `let cipher = out_enc.as_buffer().clone();`
//                                             // Let's refine CipherContext to return Vec<u8> or make output param mutable.
//                                             // For now, assume decrypted_output_buf is filled by magic.
//                                             // A better way for CipherContext:
//                                             // async fn decrypt(...) -> Result<Vec<u8>, Error>
//                                             // Or: async fn decrypt(..., output_buf: &mut Vec<u8>)
//                                             // For now, let's assume the dummy `CipherOutput::Buffer(Box::new(Vec::new()))` works as in the demo.
//                                             let temp_out_buf = Vec::new();
//                                             let mut output_holder =
//                                                 symmetric_cipher::crypto::cipher_types::CipherOutput::Buffer(
//                                                     Box::new(temp_out_buf),
//                                                 );
// 
//                                             if ctx
//                                                 .decrypt(
//                                                     symmetric_cipher::CipherInput::Bytes(
//                                                         chat.clone().encrypted_payload,
//                                                     ),
//                                                     &mut output_holder,
//                                                 )
//                                                 .await
//                                                 .is_ok()
//                                             {
//                                                 if let symmetric_cipher::CipherOutput::Buffer(dec_data_box) = output_holder {
//                                                      match chat.payload_type() { // Use .payload_type() for enum
//                                                         PayloadType::Text => {
//                                                             let text = String::from_utf8_lossy(&dec_data_box);
//                                                             println!("[{}] ({}): {}", chrono::Utc::now().format("%H:%M"), chat.sender_id, text);
//                                                         }
//                                                         PayloadType::File | PayloadType::Image => {
//                                                             println!("[{}] ({}): Received file chunk for '{}' ({} bytes)", chrono::Utc::now().format("%H:%M"), chat.sender_id, chat.filename, dec_data_box.len());
//                                                             // TODO: File reassembly logic
//                                                         }
//                                                     }
//                                                 }
//                                             } else {
//                                                 println!("[Error] Decryption failed.");
//                                             }
//                                         }
//                                         Err(e) => println!("[Error] Decryption failed: {:?}", e),
//                                     }
//                                 } else {
//                                     println!("[System] Received encrypted message from {} but no shared key established yet. IV: {:x?}", chat.sender_id, chat.iv);
//                                 }
//                             }
//                             ServerEventType::KeyExchangeData(key_data) => {
//                                 println!(
//                                     "[System] Received DH public key from {}",
//                                     key_data.from_client_id
//                                 );
//                                 if let Some(local_keypair) = &sess.dh_keypair {
//                                     let dh_params = get_standard_dh_params(); // Ensure consistency
//                                     let dh_context = DiffieHellman::new(dh_params).unwrap();
//                                     let remote_pub_key =
//                                         BigUint::from_bytes_be(&key_data.public_key_dh);
// 
//                                     match dh_context.compute_shared_secret(
//                                         &local_keypair.private_key,
//                                         &remote_pub_key,
//                                     ) {
//                                         Ok(shared_secret_bn) => {
//                                             println!(
//                                                 "[System] Shared secret computed successfully!"
//                                             );
//                                             // Derive a key for LOKI97 (e.g. 256-bit / 32 bytes) or Twofish
//                                             // THIS IS A SIMPLISTIC KDF - DO NOT USE IN PRODUCTION
//                                             let key_len = match sess
//                                                 .encryption_algorithm
//                                                 .unwrap_or(EncryptionAlgorithm::Loki97)
//                                             {
//                                                 EncryptionAlgorithm::Loki97 => 32, // LOKI97 supports 128, 192, 256 bit keys
//                                                 EncryptionAlgorithm::Twofish => 32, // Twofish supports 128, 192, 256 bit keys
//                                                 _ => 32,
//                                             };
//                                             let derived_key = derive_key_from_shared_secret(
//                                                 &shared_secret_bn,
//                                                 key_len,
//                                             );
//                                             sess.shared_secret_key = Some(derived_key.clone());
//                                             println!("[System] Symmetric key derived (first 4 bytes): {:x?}", &derived_key[..std::cmp::min(4, derived_key.len())]);
//                                         }
//                                         Err(e) => println!(
//                                             "[Error] Failed to compute shared secret: {}",
//                                             e
//                                         ),
//                                     }
//                                 } else {
//                                     println!(
//                                         "[Error] Received DH key but local keypair not generated."
//                                     );
//                                 }
//                             }
//                             ServerEventType::Error(err) => {
//                                 println!(
//                                     "[Server Error] Code: {}, Message: {}",
//                                     err.error_code, err.message
//                                 );
//                             }
//                             ServerEventType::RoomClosed(closed) => {
//                                 println!(
//                                     "[Room Closed] ID: {}, Reason: {}",
//                                     closed.room_id, closed.reason
//                                 );
//                                 if sess.current_room_id.as_ref() == Some(&closed.room_id) {
//                                     sess.current_room_id = None;
//                                     sess.encryption_algorithm = None;
//                                     sess.dh_keypair = None;
//                                     sess.shared_secret_key = None;
//                                 }
//                             }
//                             ServerEventType::ServerAck(ack) => {
//                                 println!(
//                                     "[Server ACK] For request '{}': Success: {}, Details: {}",
//                                     ack.original_request_id, ack.success, ack.details
//                                 );
//                             }
//                         }
//                     }
//                 }
//                 Err(e) => {
//                     log::error!("Error from server stream: {:?}", e);
//                     break;
//                 }
//             }
//         }
//         log::info!("Server stream ended.");
//     });
//     log::debug!("Receiver task spawned.");
// 
//     println!(
//         "[DEBUG] CLI: About to initialize Rustyline. Client ID: {}",
//         session.lock().await.client_id
//     );
//     std::io::stdout().flush().unwrap(); // Force flush to ensure it prints
// 
//     // Main input loop
//     let mut rl = match DefaultEditor::new() {
//         Ok(editor) => {
//             log::debug!("Rustyline editor created successfully.");
//             editor
//         }
//         Err(e) => {
//             log::error!("Failed to create Rustyline editor: {:?}", e);
//             return Err(Box::new(e));
//         }
//     };
// 
//     log::debug!("Rustyline editor initialized. Starting main input loop.");
//     println!("[DEBUG] CLI: Rustyline initialized. Starting input loop.");
//     std::io::stdout().flush().unwrap();
// 
//     loop {
//         let prompt_client_id = session.lock().await.client_id.clone();
//         let prompt_room_id_opt = session.lock().await.current_room_id.clone();
//         let prompt_room_display = prompt_room_id_opt.as_deref().unwrap_or("Lobby");
// 
//         let line = rl.readline(&format!(
//             "({}) {} > ",
//             prompt_client_id, prompt_room_display
//         ));
//         match line {
//             Ok(input_str) => {
//                 let input_str = input_str.trim();
//                 rl.add_history_entry(input_str.to_string())?;
//                 let parts: Vec<&str> = input_str.split_whitespace().collect();
//                 if parts.is_empty() {
//                     continue;
//                 }
// 
//                 let cmd = parts[0];
//                 let mut sess_guard = session.lock().await; // mutable access to session
// 
//                 let req_payload = match cmd {
//                     "create" if parts.len() > 1 => {
//                         let algo_str = parts[1].to_lowercase();
//                         let algo = match algo_str.as_str() {
//                             "loki97" => EncryptionAlgorithm::Loki97,
//                             "twofish" => EncryptionAlgorithm::Twofish,
//                             _ => {
//                                 println!("Unknown algorithm. Use 'loki97' or 'twofish'.");
//                                 continue;
//                             }
//                         };
//                         Some(ClientRequestType::CreateRoom(CreateRoomRequest {
//                             algorithm: algo as i32,
//                         }))
//                     }
//                     "join" if parts.len() > 1 => {
//                         Some(ClientRequestType::JoinRoom(JoinRoomRequest {
//                             room_id: parts[1].to_string(),
//                         }))
//                     }
//                     "leave" => {
//                         if let Some(room_id) = sess_guard.current_room_id.clone() {
//                             sess_guard.current_room_id = None; // Optimistically clear
//                             sess_guard.shared_secret_key = None;
//                             sess_guard.dh_keypair = None;
//                             Some(ClientRequestType::LeaveRoom(LeaveRoomRequest { room_id }))
//                         } else {
//                             println!("Not in a room.");
//                             continue;
//                         }
//                     }
//                     "sendkey" => {
//                         // Manually trigger sending DH key if needed for testing
//                         if sess_guard.current_room_id.is_some() && sess_guard.dh_keypair.is_none() {
//                             println!("[System] Generating and sending DH public key.");
//                             let dh_params = get_standard_dh_params();
//                             let dh_context = DiffieHellman::new(dh_params).unwrap();
//                             let keypair = dh_context.generate_keypair(&mut OsRng);
//                             sess_guard.dh_keypair = Some(keypair.clone());
//                             Some(ClientRequestType::SendKeyExchange(SendKeyExchangeData {
//                                 room_id: sess_guard.current_room_id.as_ref().unwrap().clone(),
//                                 public_key_dh: keypair.public_key.to_bytes_be(),
//                             }))
//                         } else {
//                             println!(
//                                 "[System] Either not in a room or key already generated/sent."
//                             );
//                             continue;
//                         }
//                     }
//                     "say" if parts.len() > 1 => {
//                         if sess_guard.current_room_id.is_none()
//                             || sess_guard.shared_secret_key.is_none()
//                         {
//                             println!("Not in a room or session key not established.");
//                             continue;
//                         }
//                         let message_text = parts[1..].join(" ");
//                         let key = sess_guard.shared_secret_key.as_ref().unwrap().clone();
//                         let algo = sess_guard.encryption_algorithm.unwrap();
// 
//                         let mut iv = vec![0u8; 16]; // 128-bit block size for LOKI97/Twofish
//                         rand::Rng::fill(&mut OsRng, &mut iv[..]);
// 
//                         let mut cipher_instance: Box<dyn SymmetricCipherWithRounds + Send + Sync> =
//                             match algo {
//                                 EncryptionAlgorithm::Loki97 => Box::new(Loki97Cipher::new(&key)),
//                                 EncryptionAlgorithm::Twofish => Box::new(Twofish::new(&key)),
//                                 _ => {
//                                     println!("[Error] Bad algo for encrypt");
//                                     continue;
//                                 }
//                             };
//                         cipher_instance
//                             .set_key(&key)
//                             .expect("Failed to set key for encryption");
// 
//                         let initial_additional_params_enc = cipher_instance
//                             .export_round_keys()
//                             .unwrap_or_else(|| key.clone());
// 
//                         let ctx = CipherContext::new(
//                             cipher_instance,
//                             CipherMode::CBC,
//                             PaddingMode::PKCS7,
//                             Some(iv.clone()),
//                             initial_additional_params_enc,
//                         );
//                         // ctx.set_key(&key).unwrap();
//                         // ctx.set_iv(iv.clone());
// 
//                         let encrypted_output_buf = Vec::new();
//                         let mut output_holder =
//                             symmetric_cipher::CipherOutput::Buffer(Box::new(encrypted_output_buf));
// 
//                         if ctx
//                             .encrypt(
//                                 symmetric_cipher::CipherInput::Bytes(
//                                     message_text.as_bytes().to_vec(),
//                                 ),
//                                 &mut output_holder,
//                             )
//                             .await
//                             .is_ok()
//                         {
//                             if let symmetric_cipher::CipherOutput::Buffer(enc_data_box) =
//                                 output_holder
//                             {
//                                 Some(ClientRequestType::SendMessage(SendMessageRequest {
//                                     room_id: sess_guard.current_room_id.as_ref().unwrap().clone(),
//                                     iv: iv.clone(),
//                                     encrypted_payload: enc_data_box.to_vec(),
//                                     payload_type: PayloadType::Text as i32,
//                                     filename: String::new(),
//                                     is_last_chunk: true,
//                                     chunk_sequence_number: 0,
//                                     
//                                 }))
//                             } else {
//                                 println!("Encrypt error");
//                                 continue;
//                             }
//                         } else {
//                             println!("Encryption failed.");
//                             continue;
//                         }
//                     }
//                     "quit" | "exit" => break,
//                     _ => {
//                         println!("Unknown command: {}", cmd);
//                         continue;
//                     }
//                 };
// 
//                 if let Some(payload) = req_payload {
//                     let client_req = ClientRequest {
//                         request_id: Uuid::new_v4().to_string(),
//                         client_id: sess_guard.client_id.clone(),
//                         timestamp: chrono::Utc::now().timestamp_millis(),
//                         request: Some(payload),
//                     };
//                     if client_tx.send(client_req).await.is_err() {
//                         log::error!("Failed to send request to server. Connection lost?");
//                         break;
//                     }
//                 }
//             }
//             Err(rustyline::error::ReadlineError::Interrupted) => {
//                 println!("CTRL-C");
//                 break;
//             }
//             Err(rustyline::error::ReadlineError::Eof) => {
//                 println!("CTRL-D");
//                 break;
//             }
//             Err(err) => {
//                 println!("Error: {:?}", err);
//                 break;
//             }
//         }
//     }
//     Ok(())
// }

fn main() {}