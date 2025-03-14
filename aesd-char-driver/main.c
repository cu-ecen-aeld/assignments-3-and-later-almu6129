/**
 * @file aesdchar.c
 * @brief Functions and data related to the AESD char driver implementation
 *
 * Based on the implementation of the "scull" device driver, found in
 * Linux Device Drivers example code.
 *
 * @author Dan Walkes
 * @date 2019-10-22
 * @copyright Copyright (c) 2019
 *
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/cdev.h>
#include <linux/string.h>
#include "aesd-circular-buffer.h"
#include <linux/fs.h> // file_operations
#include "aesdchar.h"
int aesd_major =   0; // use dynamic major
int aesd_minor =   0;

MODULE_AUTHOR("Alexander Mueller");
MODULE_LICENSE("Dual BSD/GPL");

struct aesd_dev aesd_device;

int aesd_open(struct inode *inode, struct file *filp)
{
    PDEBUG("open");

    struct aesd_dev *dev;
    //Find our structure in the relating inode with pointer math
    dev = container_of(inode->i_cdev, struct scull_dev, cdev);
    filp->private_data = dev;

    return 0;
}

int aesd_release(struct inode *inode, struct file *filp)
{
    PDEBUG("release");
    /**
     * TODO: handle release
     */
    return 0;
}

ssize_t aesd_read(struct file *filp, char __user *buf, size_t count,
                loff_t *f_pos)
{
    ssize_t retval = 0;
    PDEBUG("read %zu bytes with offset %lld",count,*f_pos);
    
    size_t spot_in_entry;
    struct aesd_buffer_entry *ret_ptr;

    ret_ptr = aesd_circular_buffer_find_entry_offset_for_fpos(filp->private_data->buf,
                                                    *f_pos, &spot_in_entry);


    if(ret_ptr == NULL) return 0;

    retval = ret_ptr -> size - (spot_in_entry + 1);                                           
    
    retval = __copy_to_user(buf, &ret_ptr[spot_in_entry], retval);

    *f_pos += ret_val;

    return retval;
}

ssize_t aesd_write(struct file *filp, const char __user *buf, size_t count,
                loff_t *f_pos)
{
    ssize_t retval = -ENOMEM;
    PDEBUG("write %zu bytes with offset %lld",count,*f_pos);
    
    if(count <= 0){
        PDEBUG("Write was called with a count of 0\n");
        return 0;
    }

    if (mutex_lock_interruptible(&dev->lock))
		return -ERESTARTSYS;

    //The case where our last data write did complete
    if(filp->private_data->ent.size == 0){

        char * alloc_mem = (char *)kmalloc(count);

        if(alloc_mem == NULL){
            PDEBUG("Malloc Failed\n");
            mutex_unlock(&filp->private_data->lock);
            return -ENOMEM;
        }

        retval = __copy_from_user(alloc_mem, buf, count);

        //What was actually copied from user space
        retval = count - retval;

        filp->private_data->ent.buffptr = alloc_mem;
        filp->private_data->ent.size = retval;

        //If we didn't reach the end of the command, return and wait for more data
        if(alloc_mem[retval - 1] != '\n'){
            mutex_unlock(&filp->private_data->lock);
            return retval;
        }
    }
    //The case where our last data write did not complete
    else{

        //Calculate the new total size of the accumulated data
        int new_size = count + filp->private_data->ent.size;

        //Append the data
        filp->private_data->ent.buffptr = (char *)krealloc(filp->private_data->ent.buffptr, new_size);

        if(alloc_mem == NULL){
            PDEBUG("Malloc Failed\n");
            mutex_unlock(&filp->private_data->lock);
            return -ENOMEM;
        }

        retval = __copy_from_user(&filp->private_data->ent.buffptr[filp->private_data->ent.size - 1], buf, count);

        //What was actually copied from user space
        retval = count - retval;

        filp->private_data->ent.size = new_size;

        //If we didn't reach the end of the command, return and wait for more data
        if(filp->private_data->ent.buffptr[new_size - 1] != '\n'){
            mutex_unlock(&filp->private_data->lock);
            return retval;
        }
    }
    
    //If we reached here we found a newline character
    aesd_circular_buffer_add_entry(filp->private_data->buf, filp->private_data->ent);

    //Reset the count local to the filp structure circular buffer entry
    filp->private_data->ent.size = 0;

    mutex_unlock(&filp->private_data->lock);
    return retval;
}
struct file_operations aesd_fops = {
    .owner =    THIS_MODULE,
    .read =     aesd_read,
    .write =    aesd_write,
    .open =     aesd_open,
    .release =  aesd_release,
};

static int aesd_setup_cdev(struct aesd_dev *dev)
{
    int err, devno = MKDEV(aesd_major, aesd_minor);

    cdev_init(&dev->cdev, &aesd_fops);
    dev->cdev.owner = THIS_MODULE;
    dev->cdev.ops = &aesd_fops;
    err = cdev_add (&dev->cdev, devno, 1);
    if (err) {
        printk(KERN_ERR "Error %d adding aesd cdev", err);
    }
    return err;
}



int aesd_init_module(void)
{
    dev_t dev = 0;
    int result;
    result = alloc_chrdev_region(&dev, aesd_minor, 1,
            "aesdchar");
    aesd_major = MAJOR(dev);
    if (result < 0) {
        printk(KERN_WARNING "Can't get major %d\n", aesd_major);
        return result;
    }
    memset(&aesd_device,0,sizeof(struct aesd_dev));

    //Initialize the muxed we use for protecting the circular buffer
    mutex_init(&aesd_device.lock);

    result = aesd_setup_cdev(&aesd_device);

    if( result ) {
        unregister_chrdev_region(dev, 1);
    }
    return result;

}

void aesd_cleanup_module(void)
{
    dev_t devno = MKDEV(aesd_major, aesd_minor);

    cdev_del(&aesd_device.cdev);

    /**
     * TODO: cleanup AESD specific poritions here as necessary
     */

    unregister_chrdev_region(devno, 1);
}



module_init(aesd_init_module);
module_exit(aesd_cleanup_module);
