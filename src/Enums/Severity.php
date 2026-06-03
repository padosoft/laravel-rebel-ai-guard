<?php

declare(strict_types=1);

namespace Padosoft\Rebel\AiGuard\Enums;

enum Severity: string
{
    case Low = 'low';
    case Medium = 'medium';
    case High = 'high';
    case Critical = 'critical';
}
