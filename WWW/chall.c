#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <string.h>

#define BUFFER_LENGTH 26

char SIGNATURE[8];

void setup(void) {
    setbuf(stdout, NULL);
    setbuf(stdin, NULL);
}

void taylor()
{
    memset(SIGNATURE, 'T', 1);
    puts("----|\\----------------- **--------------------");
    puts("----|/-----------------**---****---*****------");
    puts("---/|-----------------**---**--**----**-------");
    puts("--/-|_-------------****---******---**---------");
    puts("-|--|-\\------------****---**--**--*****-------");
    puts("_|__|_|");
    puts("  \\_|_/");
    system("date");
    putchar(SIGNATURE);
}

void lana()
{
    memset(SIGNATURE, 'L', 1);
    puts("     ;;;;;;;;;;;;;;;;;;;");
    puts("     ;;;;;;;;;;;;;;;;;;;");
    puts("     ;                 ;");
    puts("     ;                 ;");
    puts("     ;                 ;");
    puts("     ;                 ;");
    puts("     ;                 ;");
    puts("     ;                 ;");
    puts("     ;                 ;");
    puts(",;;;;;            ,;;;;;");
    puts(";;;;;;            ;;;;;;");
    puts("`;;;;'            `;;;;'");
    system("date");
    putchar(SIGNATURE);
}

void billie()
{
    memset(SIGNATURE, 'B', 1);
    puts("WAAAAAAHHHH!! WAAH, WAAHH, WAAAAAAHHHH!'");
    system("date");
    putchar(SIGNATURE);
}

void ariana()
{
    puts("Baby, baby, baeeeee ...!");
    exit(-1);
}

void adele()
{
    memset(SIGNATURE, 'A', 1);
    puts("   _________________________________________________________________________\\");
    puts("|:____|\\_________b___/______.____.__|__________._______.---.__.____________:|");
    puts("|:____|/__4____|.____$______|____|__|__________|\\__-,__|___|__|\\_______..__:|");
    puts("|:___/|___4____'`____/______|____|__|__________|___/___|___|__|\\___\"\"______:|");
    puts("|:__('|)___________________@|___(|__|__#( )___@|._____@|__@|_@|____________:|");
    puts("     \"|                              mp                                    /");
    system("date");
    putchar(SIGNATURE);
}

int main(int argc, char **argv)
{
    setup();
    char buffer[BUFFER_LENGTH];
    puts("   _______       __");
    puts(" /   ------.   / ._`_");
    puts("|  /         ~--~    \\");
    puts("| |             __    `.____________________ _^-----^");
    puts("| |  I=|=======/--\\=========================| o o o |");
    puts("\\ |  I=|=======\\__/=========================|_o_o_o_|");
    puts(" \\|                   /                       ~    ~");
    puts("   \\       .---.    .");
    puts("     -----'     ~~''");

    puts("=== THE MAGIC GUITAR ===");

    puts("Welcome all pwners to the magical guitar!!");
    puts("Are you ready to play the best song ever?");
    puts("First, tell me your name?");
    fgets(buffer, sizeof(buffer), stdin);
    printf(buffer);
    puts("Great name for an artist!");

    char menu_option;

    puts("CHOOSE A SONG TO PLAY! CHOOSE THEM WISELY SINCE U ONLY HAVE ONE CHANCE!");
    puts("a. All Too Well - Taylor Swift");
    puts("b. Chemtrails Over The Country Club - Lana Del Rey");
    puts("c. Happier Than Ever - Billie Eilish");
    puts("d. No Tears Left To Cry - Ariana Grande");
    puts("e. All I Ask - Adele");
    scanf(" %c", &menu_option);

    switch (menu_option)
    {
    case 'a':
        taylor();
        break;
    case 'b':
        lana();
        break;
    case 'c':
        billie();
        break;
    case 'd':
        ariana();
        break;
    case 'e':
        adele();
        break;
    default:
        puts("Please input the right character (a-e)!!!");
        break;
    }
}
