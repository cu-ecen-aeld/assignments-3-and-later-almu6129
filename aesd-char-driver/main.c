#include <linux/module.h>
#include <linux/init.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/cdev.h>
#include <linux/fs.h> 
#include "aesdchar.h"
#include "aesd-circular-buffer.h"
#include "aesd_ioctl.h"

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
    size_t num_bytes_in_buffer = 0;
    size_t new_fpos = *f_pos;

    struct aesd_dev *dev = filp->private_data;
    struct aesd_buffer_entry *entry;

    size_t spot_in_node = 0;
    size_t avail_in_node_rem = 0;
    size_t final_copy_num = 0;
    size_t num_actual_copied = 0;

    int how_many_nodes;
    int idx;

    PDEBUG("read %zu bytes with offset %lld",count,*f_pos);
    mutex_lock(dev->lock);
    
    if(dev->buf->full) how_many_nodes = AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
    else how_many_nodes = (dev->buf->in_offs - dev->buf->out_offs);

    for(int i = 0; i < how_many_nodes; i++){

        idx = (dev->buf->out_offs + i) % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
        num_bytes_in_buffer += dev->buf->entry[idx].size;

    }

    if(new_fpos >= num_bytes_in_buffer){

        mutex_unlock(dev->lock);
        return 0;

    }

    while(count > 0 && (entry = aesd_circular_buffer_find_entry_offset_for_fpos(dev->buf, new_fpos, &spot_in_node)) != NULL){

        avail_in_node_rem = entry->size - spot_in_node;

        if(count < avail_in_node_rem) final_copy_num = count;
        else final_copy_num = avail_in_node_rem;

        if(copy_to_user(buf, entry->buffptr + spot_in_node, final_copy_num) != 0){
            mutex_unlock(dev->lock);
            return -EFAULT;
        }

        buf = buf + final_copy_num;

        count = count - final_copy_num;

        new_fpos = new_fpos + final_copy_num;

        num_actual_copied = num_actual_copied + final_copy_num;

    }

    *f_pos = new_fpos;

    mutex_unlock(dev->lock);
    return num_actual_copied;
}

ssize_t aesd_write(struct file *filp, const char __user *buf, size_t count,
                loff_t *f_pos)
{
    struct aesd_dev *dev = filp->private_data;
    struct aesd_buffer_entry node_to_add;
    char *temp_buf_from_user = NULL;
    char *full_temp_buffer = NULL;
    char *final_buffer;
    size_t total_len;
    char *tmp_ptr = NULL;
    size_t new_offset_in_node = 0;
    char *to_free;
    size_t num_left;

    PDEBUG("write %zu bytes with offset %lld", count, *f_pos);

    temp_buf_from_user = kmalloc(count, GFP_KERNEL);
    if(temp_buf_from_user == NULL) return -ENOMEM;

    if(copy_from_user(temp_buf_from_user, buf, count)){
        kfree(temp_buf_from_user);
        return -EFAULT;
    }

    mutex_lock(dev->lock);

    total_len = dev->ent_size + count;

    full_temp_buffer = kmalloc(total_len, GFP_KERNEL);

    if(full_temp_buffer == NULL){
        kfree(temp_buf_from_user);
        mutex_unlock(dev->lock);
        return -ENOMEM;
    }

    if(dev->ent){
        memcpy(full_temp_buffer, dev->ent, dev->ent_size);
        kfree(dev->ent);
    }

    memcpy(full_temp_buffer + dev->ent_size, temp_buf_from_user, count);

    kfree(temp_buf_from_user);

    dev->ent = full_temp_buffer;

    dev->ent_size = total_len;

    while((tmp_ptr = memchr(dev->ent + new_offset_in_node, '\n', dev->ent_size - new_offset_in_node)) != NULL){

        size_t new_len = tmp_ptr - (dev->ent + new_offset_in_node) + 1;

        final_buffer = kmalloc(new_len, GFP_KERNEL);

        if(final_buffer == NULL){
            mutex_unlock(dev->lock);
            return -ENOMEM;
        }

        memcpy(final_buffer, dev->ent + new_offset_in_node, new_len);

        node_to_add.buffptr = final_buffer;

        node_to_add.size = new_len;

        to_free = aesd_circular_buffer_add_entry(dev->buf, &node_to_add);
        if(to_free) kfree(to_free);

        new_offset_in_node += new_len;
    }


    if(new_offset_in_node < dev->ent_size){

        num_left = dev->ent_size - new_offset_in_node;
        char *temp_buf = kmalloc(num_left, GFP_KERNEL);

        if(temp_buf == NULL){
            mutex_unlock(dev->lock);
            return -ENOMEM;
        }

        memcpy(temp_buf, dev->ent + new_offset_in_node, num_left);
        kfree(dev->ent);

        dev->ent = temp_buf;

        dev->ent_size = num_left;

    }else{

        kfree(dev->ent);
        dev->ent = NULL;
        dev->ent_size = 0;

    }
    mutex_unlock(dev->lock);

    *f_pos += count;
    return count;
}

loff_t aesd_llseek(struct file *filp, loff_t offset, int whence){

    struct aesd_dev *dev = filp->private_data;

    switch (whence)
    {
    case SEEK_SET:
        
        PDEBUG("Doing seek set with offset %d.\n", offset);
        mutex_lock(dev -> lock);
        if(offset < 0 || offset >= dev->buf->num_bytes){
            mutex_unlock(dev->lock);
            return -EINVAL;
        }

        filp -> f_pos = offset;
        mutex_unlock(dev->lock);

        break;
    case SEEK_CUR:

        PDEBUG("Doing seek cur with offset %d.\n", offset);
        mutex_lock(dev -> lock);
        if(filp->f_pos + offset < 0 || filp->f_pos + offset >= dev->buf->num_bytes){
            mutex_unlock(dev->lock);
            return -EINVAL;
        }

        filp -> f_pos += offset;
        mutex_unlock(dev->lock);

        break;
    case SEEK_END:

        PDEBUG("Doing seek end with offset %d.\n", offset);
        mutex_lock(dev -> lock);
        if((offset + dev->buf->num_bytes) > dev->buf->num_bytes || (offset + dev->buf->num_bytes) < 0){
            mutex_unlock(dev->lock);
            return -EINVAL;
        }

        filp -> f_pos = (dev -> buf-> num_bytes) + offset;
        mutex_unlock(dev->lock);

        break;
    default:
        PDEBUG("Ended up with invalid whence");
        break;
    }
    return 0;
}

static long aesd_adjust_file_offset(struct file *filp, int buf_off, int cmd_off){

    struct aesd_dev *dev = filp->private_data;
    int how_many_nodes;

    PDEBUG("Adjusting the FP with buff off %d and cmd off %d\n", buf_off, cmd_off);

    mutex_lock(dev->lock);

    if(dev->buf->full) how_many_nodes = AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
    else how_many_nodes = (dev->buf->in_offs - dev->buf->out_offs);

    if(buf_off >= how_many_nodes){
        mutex_unlock(dev->lock);
        return -EINVAL;
    }

    if(cmd_off >= dev -> buf -> entry[buf_off].size){
        mutex_unlock(dev->lock);
        return -EINVAL;
    }

    for(int i = 0; i < buf_off; i++){
        filp -> f_pos += (dev -> buf -> entry[i].size);
    }

    filp -> f_pos += cmd_off;

    mutex_unlock(dev->lock);

    return 0;
    
}

long aesd_ioctl(struct file *filp, unsigned int cmd, unsigned long arg){

    int retval = 0;

    switch (cmd)
    {
    case AESDCHAR_IOCSEEKTO:
        struct aesd_seekto seekto;
        if(__copy_from_user(&seekto, (const void __user *)arg, sizeof(seekto)) != 0){
            retval = -EFAULT;
        }
        else{
            retval = aesd_adjust_file_offset(filp, seekto.write_cmd, seekto.write_cmd_offset);
        }
        break;
    
    default:
        break;
    }

    return retval;

}

struct file_operations aesd_fops = {
    .owner =    THIS_MODULE,
    .read =     aesd_read,
    .write =    aesd_write,
    .open =     aesd_open,
    .release =  aesd_release,
    .llseek =   aesd_llseek,
    .unlocked_ioctl =    aesd_ioctl,
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

	if (!aesd_device.lock) {
    	return -ENOMEM;
    }

    mutex_init(aesd_device.lock);

    aesd_device.buf = kmalloc(sizeof(struct aesd_circular_buffer), GFP_KERNEL);

    if(aesd_device.buf == NULL){
        unregister_chrdev_region(dev, 1);
        return -ENOMEM;
    }

    aesd_circular_buffer_init(aesd_device.buf);
    aesd_device.ent = NULL;
    aesd_device.ent_size = 0;

    aesd_device.cdev = kmalloc(sizeof(struct cdev), GFP_KERNEL);

    if(aesd_device.cdev == NULL){
        unregister_chrdev_region(dev, 1);
        return -ENOMEM;
    }
    result = aesd_setup_cdev(&aesd_device);

    if(result) {
        unregister_chrdev_region(dev, 1);
    }
    return result;

}

void aesd_cleanup_module(void)
{
    dev_t devno = MKDEV(aesd_major, aesd_minor);

    cdev_del(aesd_device.cdev);

    kfree(aesd_device.lock);

    for(int i = 0; i < AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED; i++){

        if(aesd_device.buf->entry[i].buffptr){

            kfree(aesd_device.buf->entry[i].buffptr);
            aesd_device.buf->entry[i].buffptr = NULL;
            aesd_device.buf->entry[i].size = 0;

        }
    }

    if(aesd_device.ent){

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