# SQL migrations

The executable v1 schema lives at [schema.sql](../src/vulnmon/correlatord/persistence/schema.sql), packaged with the application so installed and source execution use the same schema. Future migrations belong alongside it and must preserve existing data. Do not maintain a second copy.
