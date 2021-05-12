from typing import Dict, List, Optional


class ApplianceDetail:
    def __init__(self, args: Dict):
        self.string_value: Optional[str] = args.get('stringValue')
        self.number_value: Optional[int] = args.get('numberValue')
        self.spk_timestamp: int = args['spkTimestamp']
        self.description: str = args['description']
        self.hacl_code: str = args['haclCode']
        self.source: str = args['source']
        self.containers: List[ApplianceDetailContainer] = list(map(ApplianceDetailContainer, args['containers']))


class ApplianceDetailContainer:
    def __init__(self, args: Dict):
        self.property_name: str = args['propertyName']
        self.t_id: str = args['tId']
        self.group: int = args['group']
        self.number_value: int = args['numberValue']
        self.translation: str = args['translation']
