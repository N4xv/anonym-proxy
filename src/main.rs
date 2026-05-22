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

    let mut buffer = [0u8; 1024]; 
    
    let bytes_read = client_stream.peek(&mut buffer).await?; 

    if bytes_read > 0 {
        if buffer[0] == 0x16 {
            let tls_version_major = buffer[1];
            let tls_version_minor = buffer[2];
            info!(
                "¡Alerta TLS Detectada! El cliente inició Handshake TLS. Versión de registro: {}.{}", 
                tls_version_major, tls_version_minor
            );
            
            let mut hex_string = String::new();
            for byte in &buffer[0..16] {
                hex_string.push_str(&format!("{:02X} ", byte));
            }
            info!("Primeros 16 bytes de la huella del cliente: [ {}]", hex_string);
        } else {
            info!("Tráfico entrante detectado, pero no parece TLS estándar (Primer byte: {:02X})", buffer[0]);
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