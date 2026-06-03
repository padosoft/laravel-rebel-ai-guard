<?php

declare(strict_types=1);

namespace Padosoft\Rebel\AiGuard\Models;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Padosoft\Rebel\AiGuard\Enums\AnomalyType;
use Padosoft\Rebel\AiGuard\Enums\CaseStatus;
use Padosoft\Rebel\AiGuard\Enums\Severity;
use Padosoft\Rebel\Core\Concerns\BelongsToTenant;

/**
 * A detected anomaly case (deterministic rules open these; the AI only explains them).
 *
 * @property string $id
 * @property string|null $tenant_id
 * @property AnomalyType $type
 * @property Severity $severity
 * @property CaseStatus $status
 * @property string $dedupe_key
 * @property array<string, mixed>|null $signals
 * @property int $events_count
 * @property CarbonImmutable $opened_at
 */
final class AnomalyCase extends Model
{
    use BelongsToTenant;
    use HasUlids;

    protected $table = 'rebel_anomaly_cases';

    /** @var list<string> */
    protected $fillable = [
        'tenant_id', 'type', 'severity', 'status', 'dedupe_key', 'signals', 'events_count', 'opened_at',
    ];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'type' => AnomalyType::class,
            'severity' => Severity::class,
            'status' => CaseStatus::class,
            'signals' => 'array',
            'events_count' => 'integer',
            'opened_at' => 'immutable_datetime',
        ];
    }
}
