int verif() {
    // Create two Roaring Bitmaps
    roaring_bitmap_t *r1 = roaring_bitmap_create();
    roaring_bitmap_t *r2 = roaring_bitmap_create();

    // Add some values to the bitmaps
    for (uint32_t i = 0; i < 100; i += 2) {
        roaring_bitmap_add(r1, i); // Add even numbers to r1
    }
    for (uint32_t i = 1; i < 100; i += 2) {
        roaring_bitmap_add(r2, i); // Add odd numbers to r2
    }

    // Verify the values in the bitmaps
    for (uint32_t i = 0; i < 100; ++i) {
        if (i % 2 == 0) {
            if (!roaring_bitmap_contains(r1, i)) {
                std::cerr << "Verification failed: " << i << " should be in r1\n";
            }
        } else {
            if (!roaring_bitmap_contains(r2, i)) {
                std::cerr << "Verification failed: " << i << " should be in r2\n";
            }
        }
    }

    // Print the contents of the bitmaps
    std::cout << "Contents of r1: ";
    roaring_uint32_iterator_t *i = roaring_create_iterator(r1);
    while (i->has_value) {
        std::cout << i->current_value << " ";
        roaring_advance_uint32_iterator(i);
    }
    roaring_free_uint32_iterator(i);
    std::cout << "\n";

    std::cout << "Contents of r2: ";
    i = roaring_create_iterator(r2);
    while (i->has_value) {
        std::cout << i->current_value << " ";
        roaring_advance_uint32_iterator(i);
    }
    roaring_free_uint32_iterator(i);
    std::cout << "\n";

    // Cleanup
    roaring_bitmap_free(r1);
    roaring_bitmap_free(r2);

    return 0;
}