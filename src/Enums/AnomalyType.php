<?php

declare(strict_types=1);

namespace Padosoft\Rebel\AiGuard\Enums;

enum AnomalyType: string
{
    case OtpBombing = 'otp_bombing';
    case SmsPumping = 'sms_pumping';
    case CredentialStuffing = 'credential_stuffing';
    case DelegationExchangeBurst = 'delegation_exchange_burst';
    case DelegationScopeProbing = 'delegation_scope_probing';
}
