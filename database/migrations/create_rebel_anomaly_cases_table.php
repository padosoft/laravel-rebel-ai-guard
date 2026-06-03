<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('rebel_anomaly_cases', function (Blueprint $table): void {
            $table->ulid('id')->primary();

            $table->string('tenant_id')->nullable();
            $table->string('type');
            $table->string('severity');
            $table->string('status')->default('open');

            // Stable key for a recurring anomaly (e.g. "otp_bombing:<identifier_hmac>") so the
            // detector updates an existing case instead of creating duplicates.
            $table->string('dedupe_key');
            $table->json('signals')->nullable();
            $table->unsignedInteger('events_count')->default(0);

            $table->timestamp('opened_at');
            $table->timestamps();

            $table->unique(['tenant_id', 'dedupe_key'], 'rebel_anomaly_dedupe');
            $table->index(['type', 'status']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('rebel_anomaly_cases');
    }
};
