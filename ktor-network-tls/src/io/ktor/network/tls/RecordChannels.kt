package io.ktor.network.tls

import kotlinx.coroutines.experimental.channels.*
import kotlinx.coroutines.experimental.io.*
import kotlin.coroutines.experimental.*

fun ByteReadChannel.tlsRecordChannel(
    coroutineContext: CoroutineContext
): ReceiveChannel<TLSRecord> = produce(coroutineContext) {
    val header = TLSRecord()

    while (readTLSRecord(header)) {
        channel.send(header)
    }
}

fun ByteWriteChannel.tlsRecordChannel(
    coroutineContext: CoroutineContext
): SendChannel<TLSRecord> = actor(coroutineContext) {
    channel.consumeEach {
        writeByte(it.type.code.toByte())
        writeShort(it.version.code.toShort())
        writeShort(it.length.toShort())

        writePacket(it.packet)
    }
}
