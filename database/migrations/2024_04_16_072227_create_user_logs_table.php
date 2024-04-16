<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        Schema::create('user_logs', function (Blueprint $table) {
            $table->id();
            $table->string('user_id');
            $table->string('user_name')->nullable();
            $table->string('user_role');
            $table->string('phone_number')->nullable();
            $table->string('email')->nullable();
            $table->string('user_ip');
            $table->string('mac_id');
            $table->boolean('is_login_successful');
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down()
    {
        Schema::dropIfExists('user_logs');
    }
};
