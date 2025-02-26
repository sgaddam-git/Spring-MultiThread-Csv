# Multithreading, Batch Mapper Processing and Spring Boot
This Repo has 

1. Creating docker containers for mysql
2. Running the liquibase scripts to create the schema and tables
3. Running the spring boot application with the local profile
4. Take user data from Csv file and store it in the database (/import API)
5. Get user data from the database and export in Csv file (/export API).
6. Multithreading to process the data in parallel.
7. Batch processing to process the data in batches.
8. 

# How to start the application

## Start the DB

### Prerequisites

* Docker installed
* mysql installed
* maven installed

### Run the MySQL container (Docker)

Run the script located in the db-scripts directory:

```bash
./start-local-db.sh
```

This will:

1. Setup variables for the MySQL
2. Create `DBO_SAMPLE` schema
3. Create master users and roles for `DBO_SAMPLE` schema
4. Start up MySQL container
5. Run the liquibase container to apply changesets
6. Make MySQL DB available to be connected on port 3306

## Start the service

Once you have the DB running you can
run gradle command :

```
gradlew clean build
```

start the service by running Spring by specifying the profile and the active profile

```
-DEnv=local -Dspring.profiles.active=local
```

### Swagger Endpoints

- Local: http://localhost:8080/data-service/swagger-ui/index.html#

- API : http://localhost:8080/data-service/data/user/import 
  - This will import the data from the csv file (resources/user/INPUT_USER_DATA.csv) to the User table in the database.)
- API : http://localhost:8080/data-service/data/user/export
  - This will export the data from the User table in the database to the csv file (OUTPUT_USER_DATA.csv)
