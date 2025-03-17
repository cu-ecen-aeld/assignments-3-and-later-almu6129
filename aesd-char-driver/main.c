#include <linux/module.h>
#include <linux/init.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/cdev.h>
#include <linux/fs.h> 
#include "aesdchar.h"
#include "aesd-circular-buffer.h"

int aesd_major =   0;
int aesd_minor =   0;

MODULE_AUTHOR("Alex Mueller");
MODULE_LICENSE("Dual BSD/GPL");

struct aesd_dev aesd_device;

int aesd_open(struct inode *inode, struct file *filp)
{
    PDEBUG("open");
    filp->private_data = &aesd_device;
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
    int num_bytes_in_buf = 0;
    int updated_fpos = *f_pos;

    struct aesd_dev *device = filp->private_data;
    struct aesd_buffer_entry *entry;

    int node_offset = 0;
    int bytes_available = 0;
    int final_num_copy_bytes = 0;
    int accum_num_copy_bytes = 0;

    int num_nodes = 0;

    int wrapped_idx;

    PDEBUG("read %zu bytes with offset %lld",count,*f_pos);

    mutex_lock(device->lock);
    
    if(device->buf->full) num_nodes = AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
    else num_nodes = (device->buf->in_offs - device->buf->out_offs);

    for (int i = 0; i < num_nodes; i++){

        wrapped_idx = (device->buf->out_offs + i) % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;

        num_bytes_in_buf += device->buf->entry[wrapped_idx].size;
    }

    //end of file condition
    if (updated_fpos >= num_bytes_in_buf){
        mutex_unlock(device->lock);
        return 0;
    }

    while((entry = aesd_circular_buffer_find_entry_offset_for_fpos(device->buf, updated_fpos, (size_t *)&node_offset)) != NULL && count > 0){

        bytes_available = entry->size - node_offset;

        //If we want collect less than a full node
        if(count < bytes_available) final_num_copy_bytes = count;
        else final_num_copy_bytes = bytes_available;

        if (__copy_to_user(buf, entry->buffptr + node_offset, final_num_copy_bytes) != 0){
            mutex_unlock(device->lock);
            return -EFAULT;
        }

        buf += final_num_copy_bytes;
        count -= final_num_copy_bytes;
        updated_fpos += final_num_copy_bytes;
        accum_num_copy_bytes += final_num_copy_bytes;

    }

    *f_pos = updated_fpos;
    mutex_unlock(device->lock);
    return accum_num_copy_bytes;
}

ssize_t aesd_write(struct file *filp, const char __user *buf, size_t count,
                loff_t *f_pos)
{
    struct aesd_dev *device = filp->private_data;

    char *temp_buffer = NULL;
    char *node_data = NULL;

    int accum_length;

    char *newline_ptr = NULL;

    size_t write_offset = 0;

    PDEBUG("write %zu bytes with offset %lld", count, *f_pos);

    temp_buffer = kmalloc(count, GFP_KERNEL);
    if (temp_buffer == NULL) return -ENOMEM;

    if (copy_from_user(temp_buffer, buf, count)){
        kfree(temp_buffer);
        return -EFAULT;
    }

    mutex_lock(device->lock);

    accum_length = device->ent_size + count;

    node_data = kmalloc(accum_length, GFP_KERNEL);

    if(node_data == NULL){

        kfree(temp_buffer);
        mutex_unlock(device->lock);
        return -ENOMEM;

    }
    if(device->ent){

        memcpy(node_data, device->ent, device->ent_size);
        kfree(device->ent);
    }
    memcpy(node_data + device->ent_size, temp_buffer, count);
    kfree(temp_buffer);

    device->ent = node_data;
    device->ent_size = accum_length;

    while((newline_ptr = memchr(device->ent + write_offset, '\n', device->ent_size - write_offset)) != NULL){

        size_t cmd_length = newline_ptr - (device->ent + write_offset) + 1;
        char *cmd_buf = kmalloc(cmd_length, GFP_KERNEL);
        if(!cmd_buf){
            mutex_unlock(device->lock);
            return -ENOMEM;
        }
        memcpy(cmd_buf, device->ent + write_offset, cmd_length);


        struct aesd_buffer_entry new_entry;
        new_entry.buffptr = cmd_buf;
        new_entry.size = cmd_length;

        const char *old_cmd = aesd_circular_buffer_add_entry(device->buf, &new_entry);
        if (old_cmd)
            kfree(old_cmd);

        write_offset += cmd_length;
    }

    if(write_offset < device->ent_size){

        size_t leftover = device->ent_size - write_offset;

        char *temp_buf = kmalloc(leftover, GFP_KERNEL);
        if (!temp_buf) {
            mutex_unlock(device->lock);
            return -ENOMEM;
        }

        memcpy(temp_buf, device->ent + write_offset, leftover);
        kfree(device->ent);
        device->ent = temp_buf;
        device->ent_size = leftover;

    }else{

        kfree(device->ent);
        device->ent = NULL;
        device->ent_size = 0;
    }

    mutex_unlock(device->lock);
    return count;
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

    cdev_init(dev->cdev, &aesd_fops);
    dev->cdev->owner = THIS_MODULE;
    dev->cdev->ops = &aesd_fops;
    err = cdev_add(dev->cdev, devno, 1);
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

    aesd_device.lock = kmalloc(sizeof(struct mutex), GFP_KERNEL);

	if (aesd_device.lock == NULL) {
    	return -ENOMEM;
    }

    mutex_init(aesd_device.lock);

    aesd_device.buf = kmalloc(sizeof(struct aesd_circular_buffer), GFP_KERNEL);

    if (aesd_device.buf == NULL) {

        unregister_chrdev_region(dev, 1);
        return -ENOMEM;

    }

    aesd_circular_buffer_init(aesd_device.buf);

    aesd_device.ent = NULL;
    aesd_device.ent_size = 0;

    aesd_device.cdev = kmalloc(sizeof(struct cdev), GFP_KERNEL);

    if (aesd_device.cdev == NULL) {

        unregister_chrdev_region(dev, 1);
        return -ENOMEM;

    }
    result = aesd_setup_cdev(&aesd_device);

    if( result ) {
        unregister_chrdev_region(dev, 1);
    }
    return result;

}

void aesd_cleanup_module(void)
{
    dev_t devno = MKDEV(aesd_major, aesd_minor);

    cdev_del(aesd_device.cdev);

    kfree(aesd_device.lock);

    for (int i = 0; i < AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED; i++) {

        if (aesd_device.buf->entry[i].buffptr) {

            kfree(aesd_device.buf->entry[i].buffptr);
            aesd_device.buf->entry[i].buffptr = NULL;
            aesd_device.buf->entry[i].size = 0;

        }
    }

    if (aesd_device.ent) {

        kfree(aesd_device.ent);
        aesd_device.ent = NULL;
        aesd_device.ent_size = 0;

    }

    kfree(aesd_device.buf);
    kfree(aesd_device.cdev);

    unregister_chrdev_region(devno, 1);
}

module_init(aesd_init_module);
module_exit(aesd_cleanup_module);