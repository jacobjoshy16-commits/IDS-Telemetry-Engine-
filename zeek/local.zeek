# Emit machine-readable logs consumed by ids-telemetry-engine.
@load base/protocols/conn
@load base/protocols/dns
@load policy/protocols/conn/known-hosts

redef LogAscii::use_json = T;
redef LogAscii::json_timestamps = JSON::TS_EPOCH;
redef Log::default_rotation_interval = 1hr;
