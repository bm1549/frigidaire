from typing import Dict


class Appliance:
    def __init__(self, args: Dict):
        self.appliance_type: str = args['appliance_type']
        self.appliance_id: str = args['appliance_id']
        self.pnc: str = args['pnc']
        self.elc: str = args['elc']
        self.sn: str = args['sn']
        self.mac: str = args['mac']
        self.cpv: str = args['cpv']
        self.nickname: str = args['nickname']

    @property
    def query_string(self) -> str:
        params = [
            f'elc={self.elc}',
            f'sn={self.sn}',
            f'pnc={self.pnc}',
            f'mac={self.mac}',  # This isn't necessary for appliance details, but it is for executing an action
        ]

        return '&'.join(params)
