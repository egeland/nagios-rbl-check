import subprocess

status = {'OK': 0, 'WARNING': 1, 'CRITICAL': 2, 'UNKNOWN': 3}
test_host = 'one.one.one.one'
test_ipv4 = '1.1.1.1'
test_ipv6 = '2606:4700:4700::1111'
crit = 99
warn = 99


def test_no_options():
    command = 'python check_rbl.py'
    result = subprocess.run(command.split())
    assert result.returncode == status['UNKNOWN']


def test_len_options():
    command = 'python check_rbl.py -w 99'
    result = subprocess.run(command.split())
    assert result.returncode == status['UNKNOWN']


def test_host_and_ip():
    command = f'python check_rbl.py -a {test_ipv4} -h {test_host}'
    result = subprocess.run(command.split())
    assert result.returncode == status['UNKNOWN']


def test_ipv4_and_ipv6():
    command = f'python check_rbl.py --ipv4 {test_ipv4} --ipv6 {test_ipv6}'
    result = subprocess.run(command.split())
    assert result.returncode == status['UNKNOWN']


def test_error_resolving():
    command = f'python check_rbl.py -h invalid.com'
    result = subprocess.run(command.split())
    assert result.returncode == status['UNKNOWN']


def test_full_run_host():
    command = f'python check_rbl.py -d -w {warn} -c {crit} -h {test_host}'
    result = subprocess.run(command.split())
    assert result.returncode == status['OK']


def test_full_run_ipv4():
    command = f'python check_rbl.py -d -w {warn} -c {crit} -a {test_ipv4}'
    result = subprocess.run(command.split())
    assert result.returncode == status['OK']


def test_full_run_ipv6():
    command = f'python check_rbl.py -d -w {warn} -c {crit} -a {test_ipv6}'
    result = subprocess.run(command.split())
    assert result.returncode == status['OK']
