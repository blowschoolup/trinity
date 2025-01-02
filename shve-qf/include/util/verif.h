#ifndef ROARING_VERIFICATION_H
#define ROARING_VERIFICATION_H

#include roaringroaring.h
#include vector
#include iostream

 Function to handle errors
void handleErrors();

 Function to create and populate Roaring Bitmaps
void createAndPopulateBitmaps(roaring_bitmap_t r1, roaring_bitmap_t r2);

 Function to verify values in Roaring Bitmaps
void verifyBitmaps(roaring_bitmap_t r1, roaring_bitmap_t r2);

 Function to print the contents of Roaring Bitmaps
void printBitmapContents(roaring_bitmap_t bitmap);

 Function to clean up Roaring Bitmaps
void cleanupBitmaps(roaring_bitmap_t r1, roaring_bitmap_t r2);

#endif  ROARING_VERIFICATION_H