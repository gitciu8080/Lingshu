-- AgentScope owns tables such as "sessions"; it needs an isolated database
-- instead of sharing the business database's public schema.
CREATE DATABASE lingshu_agentscope;
