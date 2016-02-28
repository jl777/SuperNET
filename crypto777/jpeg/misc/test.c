#include <stdio.h>
#include <memory.h>
#include <stdlib.h>
#include "jpeglib.h"

void write_JPEG_file(char * filename, int quality,void *image,int width,int height)
{
  struct jpeg_compress_struct cinfo;
  struct jpeg_error_mgr jerr;
  FILE * outfile;		/* target file */
  JSAMPROW row_pointer[1];	/* pointer to JSAMPLE row[s] */
  int row_stride;		/* physical row width in image buffer */
  cinfo.err = jpeg_std_error(&jerr);
  jpeg_create_compress(&cinfo);
  if ((outfile = fopen(filename, "wb")) == NULL)
  {
    fprintf(stderr, "can't open %s\n", filename);
    exit(1);
  }
  jpeg_stdio_dest(&cinfo, outfile);
  cinfo.image_width = width; 	/* image width and height, in pixels */
  cinfo.image_height = height;
  cinfo.input_components = 3;		/* # of color components per pixel */
  cinfo.in_color_space = JCS_RGB; 	/* colorspace of input image */
  jpeg_set_defaults(&cinfo);
  jpeg_set_quality(&cinfo, quality, TRUE /* limit to baseline-JPEG values */);
  jpeg_start_compress(&cinfo, TRUE);
  row_stride = width * 3;	/* JSAMPLEs per row in image_buffer */
  while (cinfo.next_scanline < cinfo.image_height)
  {
    row_pointer[0] = &image[cinfo.next_scanline * row_stride];
    (void) jpeg_write_scanlines(&cinfo, row_pointer, 1);
  }
  jpeg_finish_compress(&cinfo);
  fclose(outfile);
  jpeg_destroy_compress(&cinfo);
}


int main()
{
   int i; unsigned char image[100][300][3];
   memset(image,0,sizeof(image));
   for (i=0; i<300; i++)
	image[50][i][0] = 0x55, image[50][i][1] = 0xaa, image[50][i][2] = 0xff;
   write_JPEG_file("test.jpg",50,image,300,100);
   return(0);
}

