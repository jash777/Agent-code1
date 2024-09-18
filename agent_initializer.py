import asyncio
from typing import List, Dict, Any
from iptables_manager import IPTablesManager

class AgentInitializer:
    def __init__(self, iptables_manager: IPTablesManager):
        self.iptables_manager = iptables_manager

    async def initialize(self):
        await self._apply_default_rules()
        await self._block_all_traffic()
        await self._allow_loopback()
        await self._allow_agent_port()
        await self._allow_necessary_services()

    async def _apply_default_rules(self):
        # This method will keep existing rules
        print("Keeping existing rules...")

    async def _block_all_traffic(self):
        # Block all incoming traffic
        await self.iptables_manager.add_rule("all", None, "DROP", chain="INPUT")
        # Block all outgoing traffic
        await self.iptables_manager.add_rule("all", None, "DROP", chain="OUTPUT")

    async def _allow_loopback(self):
        # Allow all traffic on loopback interface
        await self.iptables_manager.add_rule("all", None, "ACCEPT", chain="INPUT", in_interface="lo")
        await self.iptables_manager.add_rule("all", None, "ACCEPT", chain="OUTPUT", out_interface="lo")

    async def _allow_agent_port(self):
        # Allow incoming traffic on agent port (25025)
        await self.iptables_manager.add_rule("tcp", 25025, "ACCEPT", chain="INPUT")
        # Allow outgoing traffic from agent port (25025)
        await self.iptables_manager.add_rule("tcp", 25025, "ACCEPT", chain="OUTPUT")

    async def _allow_necessary_services(self):
        # Allow DNS (UDP and TCP)
        await self.iptables_manager.add_rule("udp", 53, "ACCEPT", chain="OUTPUT")
        await self.iptables_manager.add_rule("tcp", 53, "ACCEPT", chain="OUTPUT")

        # Allow established and related connections
        await self.iptables_manager.add_rule("all", None, "ACCEPT", chain="INPUT", extra_args=["-m", "state", "--state", "ESTABLISHED,RELATED"])
        await self.iptables_manager.add_rule("all", None, "ACCEPT", chain="OUTPUT", extra_args=["-m", "state", "--state", "ESTABLISHED,RELATED"])

        # Allow outgoing SSH (you might want to restrict this to specific IP ranges)
        await self.iptables_manager.add_rule("tcp", 22, "ACCEPT", chain="OUTPUT")

        # You can add more rules for other necessary services here

    async def get_initial_status(self) -> Dict[str, Any]:
        rules = await self.iptables_manager.get_rules()
        return {
            "status": "initialized",
            "rules": rules
        }