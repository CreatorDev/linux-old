/*HEADER**********************************************************************
 ******************************************************************************
 ***
 *** Copyright (c) 2011, 2012, 2013, 2014 Imagination Technologies Ltd.
 *** All rights reserved
 ***
 *** This program is free software; you can redistribute it and/or
 *** modify it under the terms of the GNU General Public License
 *** as published by the Free Software Foundation; either version 2
 *** of the License, or (at your option) any later version.
 ***
 *** This program is distributed in the hope that it will be useful,
 *** but WITHOUT ANY WARRANTY; without even the implied warranty of
 *** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *** GNU General Public License for more details.
 ***
 *** You should have received a copy of the GNU General Public License
 *** along with this program; if not, write to the Free Software
 *** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 *** USA.
 ***
 *** File Name  : img-dummy.c
 ***
 *** File Description:
 *** This file contains an example of how to use the Hostport
 *** transport protocol.
 ***
 ******************************************************************************
 *END**************************************************************************/
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/printk.h>
#include <linux/proc_fs.h>
#include <linux/spinlock.h>
#include <linux/string.h>

#include <soc/img/img-transport.h>

#define FIVE_S (5 * HZ)
#define DUMMY_ID 2

static DEFINE_SPINLOCK(busy_writing);

static bool strneq(const char *c1, const char *c2, __kernel_size_t count)
{
    return 0 == strncmp(c1, c2, count);
}

static void async_request(int number, const char *err_msg)
{
	spin_lock(&busy_writing);
	if (-ETIME == img_transport_notify_timeout(number, DUMMY_ID, FIVE_S)) {
		pr_err("img-dummy : %s", err_msg);
	}
	spin_unlock(&busy_writing);
}

static void async_on(void)
{
	async_request(0xFFFF, "could not turn on async messages");
}

static void async_off(void)
{
	async_request(0, "could not turn off async messages");
}

static ssize_t write(struct file *file, const char *buf, size_t count,
			loff_t *pos)
{
	printk("%.*s\n", count, buf);
	if (strneq("on", buf, min(count,(size_t)2))) {
		pr_info("img-dummy : requesting async on\n");
		async_on();
	} else if (strneq("off", buf, min(count,(size_t)3))) {
		pr_info("img-dummy : requesting async off\n");
		async_off();
	}
	return count;
}

static struct file_operations ops = {
	.owner = THIS_MODULE,
	.write = write,
};

void received_message(u16 user_data)
{
	pr_info("img-dummy : received message 0x%04X\n", user_data);
}

/*
 * * platform driver code & data
 */
static int __init img_dummy_probe(struct platform_device *d)
{
	int result;
	struct proc_dir_entry *entry = proc_create("hsdummy", 0600, NULL, &ops);
	if (IS_ERR_OR_NULL(entry)) {
		result = PTR_ERR(entry);
		goto proc_create_failed;
	}

	result = img_transport_register_callback(received_message, DUMMY_ID);
	if (result)
		goto register_callback_failed;

	return 0;

register_callback_failed:
	remove_proc_entry("hsdummy", NULL);
proc_create_failed:
	return result;
}

static int img_dummy_remove(struct platform_device *d)
{
	img_transport_remove_callback(DUMMY_ID);
	remove_proc_entry("hsdummy", NULL);
	return 0;
}

static const struct of_device_id img_dummy_dt_ids[] = {
	{ .compatible = "img,pistachio-uccp-dummy" },
	{}
};
MODULE_DEVICE_TABLE(of, img_dummy_dt_ids);

static struct platform_driver img_dummy_pd = {
	.remove = img_dummy_remove,
	.driver = {
		.name = "img-dummy",
		.of_match_table = of_match_ptr(img_dummy_dt_ids),
	},
};

static int __init img_bt_init(void)
{
	return platform_driver_probe(&img_dummy_pd, img_dummy_probe);
}

static void __exit img_bt_exit(void)
{
	platform_driver_unregister(&img_dummy_pd);
}

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Bartosz Flis <bartosz.flis@imgtec.com>");
MODULE_DESCRIPTION("Imagination Technologies dummy Hostport endpoint \
- www.imgtec.com");

module_init(img_bt_init);
module_exit(img_bt_exit);
