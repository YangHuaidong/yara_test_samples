import subprocess

file_path = '/home/YaraAutoTestWeb/YARA_TEST/common/Archive/file_sample'
md5_file = "/home/YaraAutoTestWeb/YARA_TEST/common/Archive/list.log"


def download_():
    CMD = ["python", "/home/YaraAutoTestWeb/YARA_TEST/common/Archive/download_.py", file_path, md5_file]
    subprocess.call(CMD)


if __name__ == '__main__':
    download_()
