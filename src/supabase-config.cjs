'use strict';

// Supabase project for Neutron's account system. The anon key is meant to be
// public -- it is embedded in every Supabase client (web or native) that
// talks to this project, and it grants nothing on its own. Everything it can
// do is bounded by the RLS policies and SECURITY DEFINER functions in
// supabase/schema.sql: an authenticated user can see and touch only their own
// licenses row, and only through heartbeat(), never
// through a raw UPDATE. Leaking this key is not a credential leak the way a
// service_role key would be.
module.exports = {
  SUPABASE_URL: 'https://excombncmxteesrixrtv.supabase.co',
  SUPABASE_ANON_KEY:
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImV4Y29tYm5jbXh0ZWVzcml4cnR2Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODcwNTI5OTcsImV4cCI6MjEwMjYyODk5N30.YL1e7C2FWomU_4X1ujPT0Lq_PSnZHKID4BQJHGS7Ee8',
};
