import logging
import traceback

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.config_entries import SOURCE_REAUTH, ConfigEntry
from homeassistant.core import callback
from homeassistant.helpers import aiohttp_client
import homeassistant.helpers.config_validation as cv
from homeassistant.helpers.event import async_call_later

from .const import COORDINATOR, DOMAIN
from .eufy_security_api.api_client import ApiClient
from .model import Config, ConfigField
from .eufy_security_api.exceptions import (
    CaptchaRequiredException,
    DriverNotConnectedException,
    MultiFactorCodeRequiredException,
    WebSocketConnectionException,
)
_LOGGER = logging.getLogger(__name__)


from enum import Enum

class ValidationStatus(Enum):
    VALIDATED = 1
    CAPTCHA_REQUIRED = 2
    CAPTCHA_PASSED = 3
    MFA_REQUIRED = 4
    MFA_PASSED = 5
    SOCKET_FAILED = 6

class EufySecurityOptionFlowHandler(config_entries.OptionsFlow):
    """Option flow handler for integration"""

    def __init__(self, config_entry: ConfigEntry) -> None:
        """Initialize option flow handler"""
        self.config = Config.parse(config_entry)
        _LOGGER.debug(f"{DOMAIN} EufySecurityOptionFlowHandler - {config_entry.options}")
        self.schema = vol.Schema(
            {
                vol.Optional(ConfigField.sync_interval.name, default=self.config.sync_interval): int,
                vol.Optional(ConfigField.rtsp_server_address.name, default=self.config.rtsp_server_address): str,
                vol.Optional(ConfigField.no_stream_in_hass.name, default=self.config.no_stream_in_hass): bool,
                vol.Optional(ConfigField.name_for_custom1.name, default=self.config.name_for_custom1): str,
                vol.Optional(ConfigField.name_for_custom2.name, default=self.config.name_for_custom2): str,
                vol.Optional(ConfigField.name_for_custom3.name, default=self.config.name_for_custom3): str,
            }
        )

    async def async_step_init(self, user_input=None):
        """Form handler"""
        if user_input is not None:
            _LOGGER.debug(f"{DOMAIN} user input in option flow : %s", user_input)
            return self.async_create_entry(title="", data=user_input)

        return self.async_show_form(step_id="init", data_schema=self.schema)


class EufySecurityFlowHandler(config_entries.ConfigFlow, domain=DOMAIN):
    """Config flow handler for integration"""

    VERSION = 1
    CONNECTION_CLASS = config_entries.CONN_CLASS_CLOUD_PUSH

    @staticmethod
    @callback
    def async_get_options_flow(config_entry: ConfigEntry):
        _LOGGER.debug(f"{DOMAIN} EufySecurityOptionFlowHandler - {config_entry.data}")
        return EufySecurityOptionFlowHandler(config_entry)

    def __init__(self) -> None:
        self._errors = {}

    async def async_step_user(self, user_input=None):
        _LOGGER.debug(f"{DOMAIN} async_step_user - {user_input} - {self.__dict__}")
        self._errors = {}

        if self.source == SOURCE_REAUTH:
            coordinator = self.hass.data[DOMAIN][COORDINATOR]
            # Deal with mfa data
            if coordinator.config.mfa_required is True:
                mfa_input = user_input[ConfigField.mfa_input.name]
                await coordinator.set_mfa_and_connect(mfa_input)
            # Deal with captcha data
            elif coordinator.config.captcha_required:
                captcha_id = coordinator.config.captcha_id
                captcha_input = user_input[ConfigField.captcha_input.name]
                coordinator.config.captcha_id = None
                coordinator.config.captcha_img = None
                result_captcha = await coordinator.set_captcha_and_connect(captcha_id, captcha_input)

                _LOGGER.debug(f"{DOMAIN}  CAPTCHA SENT but returned this {result_captcha}")
                if result_captcha is None:
                    self._errors["base"] = "captcha"
                    return await self._show_config_form(user_input)


            else:
                self._errors["base"] = "auth"
                return await self._show_config_form(user_input)


            config_entry_id = None
            for entry in self._async_current_entries():
                config_entry_id = entry.entry_id

            async def try_reloading(_now):
                _LOGGER.debug(f"{DOMAIN} try_reloading start after captcha/mfa")
                await coordinator.disconnect()
                self.hass.data[DOMAIN] = {}
                await self.hass.config_entries.async_reload(config_entry_id)
                _LOGGER.debug(f"{DOMAIN} try_reloading finish after captcha/mfa")

            async_call_later(self.hass, 3, try_reloading)
            return self.async_abort(reason="reauth_successful")


        if self._async_current_entries():
            return self.async_abort(reason="single_instance_allowed")

        if user_input is not None:
            status, extra_data = await self._test_credentials(user_input[ConfigField.host.name], user_input[ConfigField.port.name])

            _LOGGER.debug(f"{DOMAIN}  TESTT CREDS RESULT {status} {extra_data}")
            if status == ValidationStatus.VALIDATED:
                return self.async_create_entry(title=user_input[ConfigField.host.name], data=user_input)
            elif status == ValidationStatus.CAPTCHA_REQUIRED:
                return self.async_show_form(
                    step_id="reauth_confirm",
                    data_schema=vol.Schema(
                        {
                            vol.Required(ConfigField.captcha_input.name): str,
                        }
                    ),
                    description_placeholders={
                        "captcha_img": '<img id="eufy_security_captcha" src="' + extra_data['captcha_img'] + '"/>'},
                )
            elif status == ValidationStatus.MFA_REQUIRED:
                return self.async_show_form(
                    step_id="reauth_confirm",
                    data_schema=vol.Schema(
                        {
                            vol.Required(ConfigField.mfa_input.name): str,
                        }
                    ),
                    description_placeholders={"captcha_img": 'Enter Multi Factor Authentication Code'},
                )
            self._errors["base"] = "auth"
            return await self._show_config_form(user_input)

        return await self._show_config_form(user_input)

    async def _show_config_form(self, user_input):  # pylint: disable=unused-argument
        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema(
                {
                    vol.Required(ConfigField.host.name, default=ConfigField.host.value): str,
                    vol.Required(ConfigField.port.name, default=ConfigField.port.value): int,
                }
            ),
            errors=self._errors,
        )

    async def _test_credentials(self, host, port) -> tuple[ValidationStatus, dict]:  # pylint: disable=unused-argument
        try:
            config = Config(host=host, port=port)
            api_client: ApiClient = ApiClient(config, aiohttp_client.async_get_clientsession(self.hass), None)
            # Test the socket first!
            await api_client.ws_connect()
            # TODO: might need to add to each one of the condition
            #await api_client.disconnect()

            try:
                await api_client.connect()
            except CaptchaRequiredException as exc:
                return ValidationStatus.CAPTCHA_REQUIRED, {"captcha_id": exc.captcha_id, "captcha_img": exc.captcha_img}
            except MultiFactorCodeRequiredException as exc:
                # todo: return the number and id!
                return ValidationStatus.MFA_REQUIRED, {"mfa_required": exc}
            except DriverNotConnectedException as exc:
                return ValidationStatus.SOCKET_FAILED, {}
            except WebSocketConnectionException as exc:
                return ValidationStatus.SOCKET_FAILED, {}

            return ValidationStatus.VALIDATED, {}
        except WebSocketConnectionException as ex:  # pylint: disable=broad-except
            _LOGGER.error(f"{DOMAIN} Exception in login : %s - traceback: %s", ex, traceback.format_exc())

        return ValidationStatus.SOCKET_FAILED, {}

    async def async_step_reauth(self, user_input=None):
        """initialize captcha flow"""
        _LOGGER.debug(f"{DOMAIN} async_step_reauth - {user_input}")
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(self, user_input=None):
        """Re-authenticate via captcha or mfa code"""
        coordinator = self.hass.data[DOMAIN][COORDINATOR]
        _LOGGER.debug(f"{DOMAIN} async_step_reauth_confirm - {coordinator.config}")
        if user_input is None:
            if coordinator.config.mfa_required is True:
                return self.async_show_form(
                    step_id="reauth_confirm",
                    data_schema=vol.Schema(
                        {
                            vol.Required(ConfigField.mfa_input.name): str,
                        }
                    ),
                    description_placeholders={"captcha_img": 'Enter Multi Factor Authentication Code'},
                )
            else:
                return self.async_show_form(
                    step_id="reauth_confirm",
                    data_schema=vol.Schema(
                        {
                            vol.Required(ConfigField.captcha_input.name): str,
                        }
                    ),
                    description_placeholders={"captcha_img": '<img id="eufy_security_captcha" src="' + coordinator.config.captcha_img + '"/>'},
                )
        return await self.async_step_user(user_input)
