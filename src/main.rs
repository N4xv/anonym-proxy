use clap::Parser;
use tokio::net::{TcpListener, TcpStream};
use tracing::{info, error, Level};
use tracing_subscriber::FmtSubscriber;
use std::error::Error;

#[derive(Parser, Debug)]
#[command(version = "1.0", about = "Proxy inverso que altera huellas TLS")]
struct Args {
    #[arg(short, long, default_value = "127.0.0.1:8080")]
    listen: String,

    #[arg(short, long)]
    target: String,
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
        let (client_stream, client_addr) = match listener.accept().await {
            Ok(val) => val,
            Err(e) => {
                error!("Error al aceptar conexión: {}", e);
                continue;
            }
        };

        info!("Nueva conexión aceptada desde: {}", client_addr);
        
        let target_address = args.target.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_connection(client_stream, target_address).await {
                error!("Error manejando la conexión de {}: {}", client_addr, e);
            }
        });
    }
}

async fn handle_connection(mut client_stream: TcpStream, target: String) -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut target_stream = TcpStream::connect(&target).await?;
    info!("Conectado con éxito al servidor destino: {}", target);

    let mut buffer = [0u8; 2048]; 
    let bytes_read = client_stream.peek(&mut buffer).await?; 

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
            let extensions_len = ((buffer[pointer] as usize) << 8) | (buffer[pointer + 1] as usize);
            pointer += 2;
            
            info!("¡Éxito! Extensiones TLS encontradas en el byte índice: {}", pointer);
            info!("Longitud total del bloque de extensiones: {} bytes", extensions_len);

            if pointer + extensions_len <= bytes_read {
                let mut ext_pointer = pointer;
                let end_of_extensions = pointer + extensions_len;
                let mut ext_count = 0;

                while ext_pointer + 4 <= end_of_extensions {
                    let ext_type = ((buffer[ext_pointer] as u16) << 8) | (buffer[ext_pointer + 1] as u16);
                    let ext_len = ((buffer[ext_pointer + 2] as usize) << 8) | (buffer[ext_pointer + 3] as usize);
                    
                    info!("-> Extensión #{}: ID [0x{:04X}] - Tamaño: {} bytes", ext_count, ext_type, ext_len);
                    
                    ext_count += 1;
                    ext_pointer += 4 + ext_len;
                }
            }
        }
    }

    let (mut client_reader, mut client_writer) = client_stream.split();
    let (mut target_reader, mut target_writer) = target_stream.split();

    let client_to_target = tokio::io::copy(&mut client_reader, &mut target_writer);
    let target_to_client = tokio::io::copy(&mut target_reader, &mut client_writer);

    tokio::select! {
        res = client_to_target => { res?; },
        res = target_to_client => { res?; },
    };

    info!("Conexión finalizada de forma segura.");
    Ok(())
}