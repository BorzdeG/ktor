package io.ktor.network.tls

import kotlinx.coroutines.experimental.channels.*
import kotlinx.coroutines.experimental.io.packet.*
import kotlinx.io.core.*
import kotlinx.io.core.ByteReadPacket
import java.security.*
import javax.net.ssl.*

fun tlsClientHandshake(
    input: ReceiveChannel<TLSRecord>,
    output: SendChannel<TLSRecord>
) {
}

private class TLSClientHandshake(
    val input: Channel<TLSRecord>,
    val output: Channel<TLSRecord>,
    val serverName: String? = null,
    randomAlgorithm: String = "NativePRNGNonBlocking"
) {
    private val random = SecureRandom.getInstance(randomAlgorithm)

    private fun initClientRandom(): ByteArray = random.generateSeed(32).apply {
        val unixTime = (System.currentTimeMillis() / 1000L)
        this[0] = (unixTime shr 24).toByte()
        this[1] = (unixTime shr 16).toByte()
        this[2] = (unixTime shr 8).toByte()
        this[3] = (unixTime shr 0).toByte()
    }

    suspend fun tlsHandshakeAndNegotiation() {
        val clientRandom = initClientRandom()
        val handshakesPacket = WritePacket()

        sendClientHello(clientRandom)
        val serverHello = receiveServerHello()
        val digest = Digest()
    }

    private suspend fun sendClientHello(clientRandom: ByteArray) {
        val header = TLSHandshakeHeader()
        with(header) {
            type = TLSHandshakeType.ClientHello
            suitesCount = SupportedSuites.size
            SupportedSuites.values.forEachIndexed { index, suite ->
                suites[index] = suite.code
            }

            random = clientRandom.copyOf()
        }

        header.serverName = serverName

        val helloBody = buildPacket {
            writeTLSClientHello(header)
        }

        val handshake = buildPacket {
            header.type = TLSHandshakeType.ClientHello
            header.length = helloBody.remaining
            writeTLSHandshake(header)
            writePacket(helloBody)
        }

        handshakesPacket.writePacket(handshake.copy())

        val record = TLSRecord().apply {
            type = TLSRecordType.Handshake

            packet = handshake
        }

        output.send(record)
    }

    private suspend fun receiveServerHello() {
    }

    private suspend fun handshake(packet: ByteReadPacket) {
        println("visit ${handshakeHeader.type}")
        when (handshakeHeader.type) {
            TLSHandshakeType.ServerHello -> {
                packet.readTLSServerHello(handshakeHeader)
                serverRandom = handshakeHeader.random.copyOf()
                cipherSuite = SupportedSuites[handshakeHeader.suites[0]]
            }
            TLSHandshakeType.Certificate -> {
                val certs = packet.readTLSCertificate(handshakeHeader)
                val x509s = certs.filterIsInstance<X509Certificate>()

                val tm: X509TrustManager = trustManager ?: findTrustManager()
                tm.checkServerTrusted(x509s.toTypedArray(), "RSA")

                serverKey = certs.firstOrNull()?.publicKey ?:
                        throw TLSException("No server certificate/public key found")

                certs.forEach {
                    it.verify(serverKey)
                }

            }
            TLSHandshakeType.CertificateRequest -> {
                val x = 0
            }
            TLSHandshakeType.ServerKeyExchange -> {
                packet.readTLSServerKeyExchange()
            }
            TLSHandshakeType.ServerDone -> {
                preSecret = random.generateSeed(48)
                preSecret[0] = 0x03
                preSecret[1] = 0x03 // TLS 1.2

                val secretHandshake = clientKeyExchange(random, handshakeHeader, serverKey!!, preSecret)
                handshakesPacket.writePacket(secretHandshake.copy())

                recordHeader.type = TLSRecordType.Handshake
                recordHeader.length = secretHandshake.remaining
                output.writePacket {
                    writeTLSHeader(recordHeader)
                }
                output.writePacket(secretHandshake)

                output.writePacket {
                    writeChangeCipherSpec(recordHeader)
                }

                val hash = doHash()
                val suite = cipherSuite!!
                masterSecret = masterSecret(SecretKeySpec(preSecret, suite.macName), TODO(), serverRandom)
                preSecret.fill(0)
                preSecret = EmptyByteArray

                val finishedBody = finished(hash, masterSecret!!)
                val finished = buildPacket {
                    handshakeHeader.type = TLSHandshakeType.Finished
                    handshakeHeader.length = finishedBody.remaining
                    writeTLSHandshake(handshakeHeader)
                    writePacket(finishedBody)
                }

                handshakesPacket.writePacket(finished.copy())
                keyMaterial = keyMaterial(
                    masterSecret!!,
                    serverRandom + TODO(),
                    suite.keyStrengthInBytes,
                    suite.macStrengthInBytes,
                    suite.fixedIvLength
                )

                val cipher = encryptCipher(suite, keyMaterial, TLSRecordType.Handshake, finished.remaining, 0, 0)
                val finishedEncrypted = finished.encrypted(cipher, 0)

                output.writePacket {
                    recordHeader.type = TLSRecordType.Handshake
                    recordHeader.length = finishedEncrypted.remaining
                    writeTLSHeader(recordHeader)
                }
                output.writePacket(finishedEncrypted)

                output.flush()
            }
            else -> throw TLSException("Unsupported TLS handshake type ${handshakeHeader.type}")
        }
    }

    private suspend fun receiveHandshake() {
        val record = output.receive()
    }

    private suspend fun receiveHandshakeFinished() {
        val encryptedPacket = readRecord()
        val recordIv = encryptedPacket.readLong()
        val cipher =
            decryptCipher(cipherSuite!!, keyMaterial, TLSRecordType.Handshake, recordHeader.length, recordIv, 0)
        val decrypted = encryptedPacket.decrypted(cipher)

        val body = decrypted.readTLSHandshake(handshakeHeader).readBytes()

        if (handshakeHeader.type != TLSHandshakeType.Finished)
            throw TLSException("TLS handshake failed: expected Finihsed record after ChangeCipherSpec but got ${handshakeHeader.type}")

        check(decrypted.isEmpty)

        val expectedFinished = serverFinished(doHash(), masterSecret!!, body.size)
        check(expectedFinished.contentEquals(body)) {
            """Handshake: ServerFinished verification failed:
                |Expected: ${expectedFinished.joinToString()}
                |Actual: ${body.joinToString()}
            """.trimMargin()
        }
    }

    private suspend fun changeCipherSpec(flag: Byte) {
        if (!readTLSRecordHeader()) throw TLSException("Handshake failed: premature end of stream")
        if (recordHeader.type == TLSRecordType.Handshake) {
            check(flag == 1.toByte()) { "Flag expected to equals 1 in handshake" }
            return
        }

        // TODO: verify flag after handshake
        throw TLSException("Unexpected record of type ${recordHeader.type} (${recordHeader.length} bytes)")
    }

    private suspend fun processHandshakeMessage(record: ByteReadPacket): Boolean {
        when (recordHeader.type) {
            TLSRecordType.Handshake -> {
                val body = record.readTLSHandshake(handshakeHeader)

                if (handshakeHeader.type != TLSHandshakeType.HelloRequest) {
                    handshakesPacket.writeTLSHandshake(handshakeHeader)
                    if (!body.isEmpty) handshakesPacket.writePacket(body.copy())
                }

                handshake(body)
            }
            TLSRecordType.ChangeCipherSpec -> {
                if (recordHeader.length != 1) throw TLSException("ChangeCipherSpec should contain just one byte but there are ${recordHeader.length}")
                val flag = record.readByte()
                changeCipherSpec(flag)

                // A Finished message is always sent immediately after a change
                // cipher spec message to verify that the key exchange and
                // authentication processes were successful.
                receiveHandshakeFinished()
                return true
            }
            TLSRecordType.Alert -> {
                val level = TLSAlertLevel.byCode(record.readByte().toInt())
                val code = TLSAlertType.byCode(record.readByte().toInt())

                throw TLSException("Received alert during handshake. Level: $level, code: $code")
            }
            else -> throw TLSException("Unsupported TLS record type ${recordHeader.type}")
        }

        return false
    }

    private fun clientKeyExchange(
        random: SecureRandom,
        handshake: TLSHandshakeHeader,
        publicKey: PublicKey,
        preSecret: ByteArray
    ): ByteReadPacket {
        require(preSecret.size == 48)

        val secretPacket = WritePacket()
        val suite = SupportedSuites[handshake.suites[0]]!!
        secretPacket.writeEncryptedPreMasterSecret(preSecret, publicKey, random)

        handshake.type = TLSHandshakeType.ClientKeyExchange
        handshake.length = secretPacket.size

        return buildPacket {
            writeTLSHandshake(handshake)
            writePacket(secretPacket.build())
        }
    }


    private fun findTrustManager(): X509TrustManager {
        val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
        tmf.init(null as KeyStore?)
        val tm = tmf.trustManagers

        return tm.first { it is X509TrustManager } as X509TrustManager
    }
}
