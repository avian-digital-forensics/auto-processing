@RD /S /Q "logs"
del "avian.db"
avian service --log-path=logs --debug
