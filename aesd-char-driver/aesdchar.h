#ifndef AESD_CHAR_DRIVER_AESDCHAR_H_
#define AESD_CHAR_DRIVER_AESDCHAR_H_

#define AESD_DEBUG 1  

#undef PDEBUG         
#ifdef AESD_DEBUG
#  ifdef __KERNEL__

#    define PDEBUG(fmt, args...) printk( KERN_DEBUG "aesdchar: " fmt, ## args)
#  else
   
#    define PDEBUG(fmt, args...) fprintf(stderr, fmt, ## args)
#  endif
#else
#  define PDEBUG(fmt, args...) 
#endif

struct aesd_dev
{
    struct aesd_circular_buffer *cbuf;   
    struct mutex *mutex;                  
    char *pending_buf;                   
    size_t pending_buf_size;               
    struct cdev *cdev;    
};


#endif /* AESD_CHAR_DRIVER_AESDCHAR_H_ */