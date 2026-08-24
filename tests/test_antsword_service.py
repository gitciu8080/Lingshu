"""AntSword API 生命周期托管测试。"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

import integrations.antsword_service as service_module
from integrations.antsword_service import AntSwordService


class _FakeProcess:
    pid = 4242
    returncode = None

    async def wait(self) -> int:
        self.returncode = 0
        return 0


class AntSwordServiceTest(unittest.IsolatedAsyncioTestCase):
    async def test_existing_service_is_reused_and_not_killed(self) -> None:
        service = AntSwordService()
        service.is_ready = AsyncMock(return_value=True)
        with patch("integrations.antsword_service.asyncio.create_subprocess_exec") as spawn:
            self.assertTrue(await service.start())
            await service.stop()
        spawn.assert_not_called()
        self.assertFalse(service.started_by_api)

    async def test_owned_process_group_is_stopped(self) -> None:
        with tempfile.TemporaryDirectory(prefix="lingshu-antsword-test-") as tmp:
            root = Path(tmp)
            executable = root / "AntSword"
            executable.write_bytes(b"test")
            executable.chmod(0o755)
            process = _FakeProcess()
            service = AntSwordService(executable, startup_timeout=1)
            service.is_ready = AsyncMock(side_effect=[False, True, False, False])

            with (
                patch.object(service_module, "_PROJECT_ROOT", root),
                patch.object(service, "_launch_command", return_value=[str(executable)]),
                patch(
                    "integrations.antsword_service.asyncio.create_subprocess_exec",
                    new=AsyncMock(return_value=process),
                ),
                patch("integrations.antsword_service.os.killpg") as killpg,
            ):
                self.assertTrue(await service.start())
                self.assertTrue(service.started_by_api)
                await service.stop()

            killpg.assert_called_once_with(4242, service_module.signal.SIGTERM)
            self.assertFalse(service.started_by_api)
            self.assertIsNone(service.process)


if __name__ == "__main__":
    unittest.main()
