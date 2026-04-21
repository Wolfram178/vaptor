def decide_scans(open_ports):
    actions = {
        "http": False,
        "ftp": False,
        "ssh": False,
        "smb": False,
    }

    for port in open_ports:
        if port in [80, 8080, 8000]:
            actions["http"] = True
        elif port == 21:
            actions["ftp"] = True
        elif port == 22:
            actions["ssh"] = True
        elif port == 445:
            actions["smb"] = True

    return actions