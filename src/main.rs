use clap::Parser;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{info, error, warn, Level};
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
// -- correccion y posible mejora
// cada extension TLS tiene tipo + datos, nada del otro mundo
struct TlsExtension {
    ext_type: [u8; 2],
    ext_data: Vec<u8>,
}

// xorshift64 basico pa no depender de rand
// no es criptograficamente seguro pero pa shufflear extensiones va bien
fn pseudorandom_shuffle(extensions: &mut Vec<TlsExtension>) {
    let mut seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;

    // fallback por si el reloj devuelve 0 por alguna razon rara
    if seed == 0 { seed = 0xACE1; }

    let n = extensions.len();
    if n < 2 { return; }

    // fisher-yates shuffle, lo de toda la vida
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

    info!("Escuchando en {}", args.listen);
    info!("Target: {}", args.target);

    let listener = TcpListener::bind(&args.listen).await?;

    // loop principal, acepta conexiones y las spawnea
    // cada conexion va en su propia tarea de tokio pa no bloquear
    loop {
        let (client_stream, client_addr) = match listener.accept().await {
            Ok(val) => val,
            Err(e) => {
                error!("fallo al aceptar conexion: {}", e);
                continue;
            }
        };

        info!("nueva conexion desde {}", client_addr);
        let target_address = args.target.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_connection(client_stream, target_address).await {
                error!("error en la conexion: {}", e);
            }
        });
    }
}

async fn handle_connection(
    mut client_stream: TcpStream,
    target: String,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    // primero conectamos al destino antes de leer nada
    let mut target_stream = TcpStream::connect(&target).await?;

    // TODO: hacer esto dinamico segun el MTU real, 4096 puede quedarse corto
    let mut buffer = vec![0u8; 4096];
    let bytes_read = client_stream.read(&mut buffer).await?;

    // comprobamos si es un ClientHello de TLS
    // 0x16 = content type Handshake, 0x01 = HandshakeType ClientHello
    if bytes_read > 5 && buffer[0] == 0x16 && buffer[5] == 0x01 {
        info!("ClientHello detectado, mutando extensiones...");

        // saltamos campos fijos del ClientHello:
        // 2 bytes version + 32 bytes random = 34 bytes, mas el header
        let mut pointer = 43;

        // session id (longitud variable)
        if pointer < bytes_read {
            let session_id_len = buffer[pointer] as usize;
            pointer += 1 + session_id_len;
        }

        // cipher suites (longitud variable, 2 bytes de longitud)
        if pointer + 2 <= bytes_read {
            let cipher_suites_len = ((buffer[pointer] as usize) << 8) | (buffer[pointer + 1] as usize);
            pointer += 2 + cipher_suites_len;
        }

        // compression methods (casi siempre 0x00 null, pero hay q parsearlo igual)
        if pointer + 1 <= bytes_read {
            let comp_methods_len = buffer[pointer] as usize;
            pointer += 1 + comp_methods_len;
        }

        // aqui empieza el bloque de extensiones
        if pointer + 2 <= bytes_read {
            let original_extensions_len =
                ((buffer[pointer] as usize) << 8) | (buffer[pointer + 1] as usize);
            let ext_data_start = pointer + 2;
            let end_of_extensions = ext_data_start + original_extensions_len;

            if end_of_extensions <= bytes_read {
                let mut ext_pointer = ext_data_start;
                let mut extensions: Vec<TlsExtension> = Vec::new();

                // parseamos cada extension: 2 bytes tipo + 2 bytes longitud + datos
                while ext_pointer + 4 <= end_of_extensions {
                    let ext_type = [buffer[ext_pointer], buffer[ext_pointer + 1]];
                    let ext_len = ((buffer[ext_pointer + 2] as usize) << 8)
                        | (buffer[ext_pointer + 3] as usize);

                    let data_start = ext_pointer + 4;
                    let data_end = data_start + ext_len;

                    if data_end <= end_of_extensions {
                        extensions.push(TlsExtension {
                            ext_type,
                            ext_data: buffer[data_start..data_end].to_vec(),
                        });
                    } else {
                        warn!("extension malformada, saltando...");
                    }

                    ext_pointer = data_end;
                }

                info!("encontradas {} extensiones, shuffleando", extensions.len());
                pseudorandom_shuffle(&mut extensions);

                // rearmamos el payload de extensiones con el nuevo orden
                let mut new_extensions_payload: Vec<u8> = Vec::new();
                for ext in extensions {
                    new_extensions_payload.extend_from_slice(&ext.ext_type);
                    let len_bytes = (ext.ext_data.len() as u16).to_be_bytes();
                    new_extensions_payload.extend_from_slice(&len_bytes);
                    new_extensions_payload.extend_from_slice(&ext.ext_data);
                }

                let new_ext_len = new_extensions_payload.len();

                // reconstruimos el paquete completo con los nuevos datos
                let mut mutated_packet: Vec<u8> = Vec::new();
                mutated_packet.extend_from_slice(&buffer[0..pointer]);
                mutated_packet.extend_from_slice(&(new_ext_len as u16).to_be_bytes());
                mutated_packet.extend_from_slice(&new_extensions_payload);

                // si habia datos despues de las extensiones los mantenemos
                if end_of_extensions < bytes_read {
                    mutated_packet.extend_from_slice(&buffer[end_of_extensions..bytes_read]);
                }

                // recalculamos longitud del Handshake (bytes 6-8, formato de 3 bytes big-endian)
                let new_handshake_len = (mutated_packet.len() - 5 - 4) as u32;
                mutated_packet[6..9].copy_from_slice(&new_handshake_len.to_be_bytes()[1..4]);

                // recalculamos longitud del TLS record (bytes 3-4)
                let new_record_len = (mutated_packet.len() - 5) as u16;
                mutated_packet[3..5].copy_from_slice(&new_record_len.to_be_bytes());

                target_stream.write_all(&mutated_packet).await?;
            } else {
                // extensiones truncadas, mandamos el paquete sin tocar
                warn!("extensiones fuera de bounds, forwarding sin modificar");
                target_stream.write_all(&buffer[0..bytes_read]).await?;
            }
        } else {
            target_stream.write_all(&buffer[0..bytes_read]).await?;
        }
    } else if bytes_read > 0 {
        // no es TLS, forwarding directo
        target_stream.write_all(&buffer[0..bytes_read]).await?;
    }

    // a partir de aqui bidireccional puro con tokio::io::copy
    // select! para cerrar ambos lados cuando uno termine
    let (mut cr, mut cw) = client_stream.split();
    let (mut tr, mut tw) = target_stream.split();

    tokio::select! {
        res = tokio::io::copy(&mut cr, &mut tw) => { res?; },
        res = tokio::io::copy(&mut tr, &mut cw) => { res?; },
    };

    Ok(())
}
