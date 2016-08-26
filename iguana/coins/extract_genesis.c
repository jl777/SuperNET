#include <stdio.h>
int main()
{
FILE *fp;
if ( (fp= fopen("blk00000.dat","rb")) != 0 )
{
int i,c;
for (i=0; i<88; i++)
{
c = fgetc(fp);
if ( i >= 8 )
printf("%02x",c);
}
printf("\n");
fclose(fp);
}
}
