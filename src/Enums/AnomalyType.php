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

    // Stream delle routine schedulate (laravel-routines): un'automazione che gira quando non c'e'
    // nessuno a guardarla sbaglia in modi che non producono errori — vedi Detection\RoutineRules.
    case RoutineFireBurst = 'routine_fire_burst';
    case RoutineFailureLoop = 'routine_failure_loop';
    case RoutineApprovalStarvation = 'routine_approval_starvation';
    case RoutineMandateProbing = 'routine_mandate_probing';
}
