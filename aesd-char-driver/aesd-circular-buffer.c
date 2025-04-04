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
 * @return the struct aesd_buffer_entry 
 */
struct aesd_buffer_entry *aesd_circular_buffer_find_entry_offset_for_fpos(struct aesd_circular_buffer *buffer,
            size_t char_offset, size_t *entry_offset_byte_rtn )
{
    int j = buffer->out_offs;
    int total_num = 0;
    int num_nodes = 0;

    while (num_nodes < AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED) {

        if((!buffer->full) && (j == buffer->in_offs)){
            break;
        }

        if(char_offset < (total_num + buffer->entry[j].size)){

            *entry_offset_byte_rtn = char_offset - total_num;

            return &buffer->entry[j];
        }

        total_num += buffer->entry[j].size;

        j = (j + 1) % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;

        num_nodes++;
    }


    return NULL;
}

/**
* Adds entry @param add_entry to @param buffer in the location specified in buffer->in_offs.
* If the buffer was already full, overwrites the oldest entry and advances buffer->out_offs to the
* new start location.
* Any necessary locking must be handled by the caller
* Any memory referenced in @param add_entry must be allocated by and/or must have a lifetime managed by the caller.
* @return NULL or the pointer to the node that was overwritten
*/
const char *aesd_circular_buffer_add_entry(struct aesd_circular_buffer *buffer, const struct aesd_buffer_entry *add_entry)
{
    const char *overwritten_node = NULL;

    if (buffer->full) {

        overwritten_node = buffer->entry[buffer->out_offs].buffptr;

        buffer -> num_bytes -= buffer->entry[buffer->out_offs].size;

        buffer->out_offs = (buffer->out_offs + 1) % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
    }

    buffer->entry[buffer->in_offs] = *add_entry;

    buffer -> num_bytes += add_entry -> size;

    buffer->in_offs = (buffer->in_offs + 1) % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;

    //If we are equal after the incrementation it means we are now full
    if (buffer->in_offs == buffer->out_offs) {

        buffer->full = true;

    } else {

        buffer->full = false;

    }

    return overwritten_node;
}

/**
* Initializes the circular buffer described by @param buffer to an empty struct
*/
void aesd_circular_buffer_init(struct aesd_circular_buffer *buffer)
{
    memset(buffer, 0, sizeof(struct aesd_circular_buffer));
}