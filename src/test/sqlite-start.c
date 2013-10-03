#include "stdio.h"
#include "sqlite3.h"
#include "stdlib.h"

/* Create Table query */
//#define QUERY "create table tab00( id smallint, desc varchar(20) )"
/* Display Table query */
//#define QUERY "select * from tab00"
/* Insert into Table query */
#define QUERY "insert into tab00 values( 233, 'desc for item num 233')"
/* Misc */
//#define QUERY "create table tab00( id smallint, desc varchar(20) )"

// gVar's 
sqlite3 *db;
char *eMsg = 0;
int rc;

// callback function to print results of exectuted query...
static int callback(void *notUsed, int argc, char **argv, char **azColName){

        int i;

        for(i=0;i<argc;i++)
                printf("%s = %s\n",azColName[i],argv[i] ? argv[i] : "NULL");

        printf("\n");

        return 0;
}


// Initialize Database
//  Location : /root/.packet_base.db
void init_DB(void){

        // try opening the db file
        rc = sqlite3_open("/root/.packet_base.db",&db);

        // check if its opened
        if(rc){

                printf("\n\nProblem opening db..\n\n");
                sqlite3_close(db);
                exit(-1);
        }

 
}// end of init_DB(void)


// Execute Query
void exec_Query(void){

        // try executing the QUERY
       //rc = sqlite3_exec(db,"select * from tab00;",callback,0,&eMsg);
       rc = sqlite3_exec(db,QUERY,callback,0,&eMsg);

        if( rc != SQLITE_OK ){

                printf("\n\nError executing query..\n\n");
                sqlite3_close(db);
                exit(-1);
        }
}


int main(int argc, char* argv[]){

         
        // init DB
        init_DB( );

        // exectue QUERY
        exec_Query( );

        // close DB
        sqlite3_close(db);

        return 0;

}
