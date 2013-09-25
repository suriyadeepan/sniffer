#include "stdio.h"
#include "sqlite3.h"

static int callback(void *notUsed, int argc, char **argv, char **azColName){

        int i;

        for(i=0;i<argc;i++)
                printf("%s = %s\n",azColName[i],argv[i] ? argv[i] : "NULL");

        printf("\n");

        return 0;
}

int main(int argc, char* argv[]){

        sqlite3 *db;
        char *eMsg = 0;
        int rc;

        rc = sqlite3_open("test.db", &db); 
        
        if(rc){

                printf("\n\nProblem opening db..\n\n");
                sqlite3_close(db);
                return -1;

        }

        rc = sqlite3_exec(db,"select * from tab00;",callback,0,&eMsg);

        if( rc != SQLITE_OK ){

                printf("\n\nError executing query..\n\n");
                sqlite3_close(db);
                return -1;
        }

        sqlite3_close(db);

        return 0;

}
