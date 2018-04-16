package io.ktor.network.tls

import io.ktor.http.cio.internals.*
import io.ktor.network.sockets.*
import kotlinx.coroutines.experimental.channels.*
import kotlinx.coroutines.experimental.io.*
import kotlinx.io.core.*
import kotlin.coroutines.experimental.*

internal class TLSClientSession(
    val input: ReceiveChannel<TLSRecord>,
    val output: SendChannel<TLSRecord>,
    val coroutineContext: CoroutineContext
) : AReadable, AWritable {
    private var readerJob: ReaderJob? = null
    private var writerJob: WriterJob? = null

    private var cipherSuite: CipherSuite? = null
    private var keyMaterial: ByteArray = EmptyByteArray

//    private val handshakeHeader = TLSHandshakeHeader()
//    val trustManager: X509TrustManager? = null,
//    private var serverRandom: ByteArray = EmptyByteArray
//    private var serverKey: PublicKey? = null
//
//    private var preSecret = EmptyByteArray
//    private var masterSecret: SecretKey? = null


    override fun attachForReading(channel: ByteChannel): WriterJob {
        writerJob = writer(coroutineContext, channel) {
            appDataInputLoop(this.channel)
        }
        return writerJob!!
    }

    override fun attachForWriting(channel: ByteChannel): ReaderJob {
        readerJob = reader(coroutineContext, channel) {
            appDataOutputLoop(this.channel)
        }
        return readerJob!!
    }

    private suspend fun appDataInputLoop(pipe: ByteWriteChannel) {
        var seq = 1L
        input.consumeEach { record ->
            val packet = record.packet
            when (record.type) {
                TLSRecordType.ApplicationData -> {
                    val recordIv = packet.readLong()
                    val cipher =
                        decryptCipher(cipherSuite!!, keyMaterial, record.type, record.length, recordIv, seq)
                    val decrypted = packet.decrypted(cipher)

                    pipe.writePacket(decrypted)
                    pipe.flush()
                }
                TLSRecordType.Alert -> {
                    val recordIv = packet.readLong()
                    val cipher =
                        decryptCipher(cipherSuite!!, keyMaterial, record.type, record.length, recordIv, seq)
                    val decrypted = packet.decrypted(cipher)

                    val fatal = decrypted.readByte() == 2.toByte()
                    val code = decrypted.readByte()

                    if (fatal) {
                        pipe.close(TLSException("Fatal: server alerted with description code $code"))
                    } else {
                        if (code != 0.toByte()) {
                            println("Got TLS warning $code")
                        }
                        pipe.close()
                    }
                    return
                }
                else -> throw TLSException("Unexpected record ${record.type} (${record.length} bytes)")
            }

            seq++
        }
    }

    private suspend fun appDataOutputLoop(pipe: ByteReadChannel) {
        var seq = 1L
        val buffer = DefaultByteBufferPool.borrow()

        try {
            while (true) {
                buffer.clear()
                val rc = pipe.readAvailable(buffer)
                if (rc == -1) break

                buffer.flip()
                val cipher = encryptCipher(cipherSuite!!, keyMaterial, TLSRecordType.ApplicationData, rc, seq, seq)
                val content = buildPacket {
                    writeFully(buffer)
                }

                val encrypted = content.encrypted(cipher, seq)
                output.send(TLSRecord().apply {
                    type = TLSRecordType.ApplicationData
                    version = TLSVersion.TLS12
                    length = encrypted.remaining
                    packet = encrypted
                })

                seq++
            }
        } finally {
            DefaultByteBufferPool.recycle(buffer)
        }
    }

    companion object {
        private val EmptyByteArray = ByteArray(0)
    }
}