use clap::Parser;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{info, error, Level};
use tracing_subscriber::FmtSubscriber;
use std::error::Error;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Parser, Debug)]
#[command(version = "1.0", about = "Proxy inverso que altera huellas TLS")]
struct Args {
    #[arg(short, long, default_value = "127.0.0.1:8080")]
    listen: String,

    #[arg(short, long)]
    target: String,
}

struct TlsExtension {
    ext_type: [u8; 2],
    ext_data: Vec<u8>,
}

fn pseudorandom_shuffle(extensions: &mut Vec<TlsExtension>) {
    let mut seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;

    if seed == 0 { seed = 0xACE1; }

    let n = extensions.len();
    if n < 2 { return; }

    for i in (1..n).rev() {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        let j = (seed % (i as u64 + 1)) as usize;
        extensions.swap(i, j);
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    let args = Args::parse();

    info!("Iniciando Proxy Anónimo en {}", args.listen);
    info!("Redirigiendo tráfico hacia {}", args.target);

    let listener = TcpListener::bind(&args.listen).await?;

    loop {
        let (client_stream, _client_addr) = match listener.accept().await {
            Ok(val) => val,
            Err(e) => {
                error!("Error al aceptar conexión: {}", e);
                continue;
            }
        };

        let target_address = args.target.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_connection(client_stream, target_address).await {
                error!("Error manejando la conexión: {}", e);
            }
        });
    }
}

async fn handle_connection(mut client_stream: TcpStream, target: String) -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut target_stream = TcpStream::connect(&target).await?;

    let mut buffer = vec![0u8; 4096];
    let bytes_read = client_stream.read(&mut buffer).await?;

    if bytes_read > 5 && buffer[0] == 0x16 && buffer[5] == 0x01 {
        let mut pointer = 43;

        if pointer < bytes_read {
            let session_id_len = buffer[pointer] as usize;
            pointer += 1 + session_id_len;
        }

        if pointer + 2 <= bytes_read {
            let cipher_suites_len = ((buffer[pointer] as usize) << 8) | (buffer[pointer + 1] as usize);
            pointer += 2 + cipher_suites_len;
        }

        if pointer + 1 <= bytes_read {
            let comp_methods_len = buffer[pointer] as usize;
            pointer += 1 + comp_methods_len;
        }

        if pointer + 2 <= bytes_read {
            let original_extensions_len = ((buffer[pointer] as usize) << 8) | (buffer[pointer + 1] as usize);
            let ext_data_start = pointer + 2;
            let end_of_extensions = ext_data_start + original_extensions_len;

            if end_of_extensions <= bytes_read {
                let mut ext_pointer = ext_data_start;
                let mut extensions = Vec::new();

                while ext_pointer + 4 <= end_of_extensions {
                    let ext_type = [buffer[ext_pointer], buffer[ext_pointer + 1]];
                    let ext_len = ((buffer[ext_pointer + 2] as usize) << 8) | (buffer[ext_pointer + 3] as usize);
                    
                    let data_start = ext_pointer + 4;
                    let data_end = data_start + ext_len;
                    
                    if data_end <= end_of_extensions {
                        extensions.push(TlsExtension {
                            ext_type,
                            ext_data: buffer[data_start..data_end].to_vec(),
                        });
                    }
                    ext_pointer = data_end;
                }

                info!("Modificando huella TLS. Cantidad de extensiones detectadas: {}", extensions.len());
                pseudorandom_shuffle(&mut extensions);

                let mut new_extensions_payload = Vec::new();
                for ext in extensions {
                    new_extensions_payload.extend_from_slice(&ext.ext_type);
                    let len_bytes = (ext.ext_data.len() as u16).to_be_bytes();
                    new_extensions_payload.extend_from_slice(&len_bytes);
                    new_extensions_payload.extend_from_slice(&ext.ext_data);
                }

                let new_ext_len = new_extensions_payload.len();
                
                let mut mutated_packet = Vec::new();
                mutated_packet.extend_from_slice(&buffer[0..pointer]);
                mutated_packet.extend_from_slice(&(new_ext_len as u16).to_be_bytes());
                mutated_packet.extend_from_slice(&new_extensions_payload);

                if end_of_extensions < bytes_read {
                    mutated_packet.extend_from_slice(&buffer[end_of_extensions..bytes_read]);
                }

                let new_handshake_len = (mutated_packet.len() - 5 - 4) as u32;
                let handshake_len_bytes = &new_handshake_len.to_be_bytes()[1..4];
                mutated_packet[6..9].copy_from_slice(handshake_len_bytes);

                let new_record_len = (mutated_packet.len() - 5) as u16;
                let record_len_bytes = new_record_len.to_be_bytes();
                mutated_packet[3..5].copy_from_slice(&record_len_bytes);

                target_stream.write_all(&mutated_packet).await?;
            } else {
                target_stream.write_all(&buffer[0..bytes_read]).await?;
            }
        } else {
            target_stream.write_all(&buffer[0..bytes_read]).await?;
        }
    } else if bytes_read > 0 {
        target_stream.write_all(&buffer[0..bytes_read]).await?;
    }

    let (mut client_reader, mut client_writer) = client_stream.split();
    let (mut target_reader, mut target_writer) = target_stream.split();

    let client_to_target = tokio::io::copy(&mut client_reader, &mut target_writer);
    let target_to_client = tokio::io::copy(&mut target_reader, &mut client_writer);

    tokio::select! {
        res = client_to_target => { res?; },
        res = target_to_client => { res?; },
    };

    Ok(())
}