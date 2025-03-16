/**
 * @file aesd-circular-buffer.c
 * @brief Functions and data related to a circular buffer imlementation
 *
 * @author Dan Walkes
 * @date 2020-03-01
 * @copyright Copyright (c) 2020
 *
 */

#ifdef __KERNEL__
#include <linux/string.h>
#else
#include <string.h>
#endif

#include "aesd-circular-buffer.h"

/**
 * @param buffer the buffer to search for corresponding offset.  Any necessary locking must be performed by caller.
 * @param char_offset the position to search for in the buffer list, describing the zero referenced
 *      character index if all buffer strings were concatenated end to end
 * @param entry_offset_byte_rtn is a pointer specifying a location to store the byte of the returned aesd_buffer_entry
 *      buffptr member corresponding to char_offset.  This value is only set when a matching char_offset is found
 *      in aesd_buffer.
 * @return the struct aesd_buffer_entry structure representing the position described by char_offset, or
 * NULL if this position is not available in the buffer (not enough data is written).
 */
struct aesd_buffer_entry *aesd_circular_buffer_find_entry_offset_for_fpos(struct aesd_circular_buffer *buffer,
            size_t char_offset, size_t *entry_offset_byte_rtn )
{
    /*So we don't de-reference a null ptr*/
    if(buffer == NULL || entry_offset_byte_rtn == NULL){
        return NULL;
    }

    int8_t fill_level;
    int total_count = 0;

    if(buffer -> full) fill_level = AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
    else{
        if(buffer -> in_offs >= buffer -> out_offs){
            fill_level = buffer -> in_offs - buffer -> out_offs;
        }
        else{
            fill_level = buffer -> out_offs - buffer -> in_offs;
        }
    }

    if(char_offset == 0 && fill_level > 0){
        *entry_offset_byte_rtn = 0;
        return &buffer -> entry[buffer -> out_offs];
    }

    for(int i = buffer -> out_offs; i < fill_level; i = ((i + 1) % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED)){
        for(int j = 0; j < buffer -> entry[i].size; j++){
            if(total_count == char_offset){
                *entry_offset_byte_rtn = j;
                return &buffer -> entry[i];
            }
            if(total_count > char_offset) return NULL;
            total_count++;
        }
    }

    return NULL;
}

/**
* Adds entry @param add_entry to @param buffer in the location specified in buffer->in_offs.
* If the buffer was already full, overwrites the oldest entry and advances buffer->out_offs to the
* new start location.
* Any necessary locking must be handled by the caller
* Any memory referenced in @param add_entry must be allocated by and/or must have a lifetime managed by the caller.
*/
struct aesd_buffer_entry *aesd_circular_buffer_add_entry(struct aesd_circular_buffer *buffer, const struct aesd_buffer_entry *add_entry)
{
    /*Quick exit if we are going to try and dereference a null ptr*/
    if(buffer == NULL || add_entry == NULL) return NULL;

    /*Full buffer condition*/
    if((buffer -> in_offs == buffer -> out_offs) && (buffer -> full)){

        void * item_to_free = (void *)&buffer -> entry[buffer -> in_offs];
	
        buffer -> entry[buffer -> in_offs] = *add_entry;
	

        buffer -> in_offs = ((buffer -> in_offs + 1) % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED);
        buffer -> out_offs = ((buffer -> out_offs + 1) % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED);

        return item_to_free;
    }
    /*Not full buffer condition*/
    else{

        buffer -> entry[buffer -> in_offs] = *add_entry;

        int prev_off = buffer -> in_offs;
        buffer -> in_offs = ((buffer -> in_offs + 1) % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED);

        if(buffer -> in_offs == buffer -> out_offs){
            if(prev_off < buffer -> out_offs || prev_off == (AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED - 1)){
                buffer -> full = true;
            }
        }
    }
    return NULL;
}

/**
* Initializes the circular buffer described by @param buffer to an empty struct
*/
void aesd_circular_buffer_init(struct aesd_circular_buffer *buffer)
{
    memset(buffer,0,sizeof(struct aesd_circular_buffer));
    buffer -> in_offs = 0;
    buffer -> out_offs = 0;
}
