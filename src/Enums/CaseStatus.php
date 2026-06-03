<?php

declare(strict_types=1);

namespace Padosoft\Rebel\AiGuard\Enums;

enum CaseStatus: string
{
    case Open = 'open';
    case Acknowledged = 'acknowledged';
    case Closed = 'closed';
}
