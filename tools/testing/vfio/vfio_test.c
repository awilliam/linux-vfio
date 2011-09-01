/*
 * Simple user test program for vfio group/device/iommu framework
 *
 * Copyright (C) 2011 Red Hat, Inc.  All rights reserved.
 * 	Author: Alex Williamson <alex.williamson@redhat.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../../../include/linux/vfio.h"

struct group {
	int fd;
	unsigned int number;
	struct group *next;
};

struct group *group_list = NULL;

struct device {
	int fd;
	char *name;
	struct device *next;
};

struct device *device_list = NULL;

struct iommu {
	int fd;
	struct device *next;
};

struct iommu *iommu_list = NULL;

void print_group(unsigned int number)
{
	struct group *group = group_list;
	char buf[4096];
	int ret;

	for (; group && group->number != number; group = group->next);

	if (!group) {
		fprintf(stderr, "Group %u not found\n", number);
	} else {
		ret = pread(group->fd, buf, sizeof(buf), 0);
		if (ret < 0) {
			fprintf(stderr, "Error reading group %u (%s)\n",
				group, strerror(errno));
			return;
		}
		fprintf(stdout, "---- Group %u (fd %d) begin ----\n",
			number, group->fd);
		fprintf(stdout, "%s", buf);
		fprintf(stdout, "---- Group %u end ----\n", number);
	}
}

void print_device(struct device *device)
{
	fprintf(stdout, "---- Device %s (fd %d) ----\n",
		device->name, device->fd);
}

int do_device()
{
	char cmd[256];
	int ret;

	while (1) {
		fprintf(stdout, "device command: ");
		fscanf(stdin, "%s", cmd);

		if (!strcmp(cmd, "quit") || !strcmp(cmd, "exit") ||
		    !strcmp(cmd, "q"))
			return 0;

		if (!strcmp(cmd, "help") || !strcmp(cmd, "h")) {
			fprintf(stdout, "[h]elp - this message\n");
			fprintf(stdout, "[o]pen - open device\n");
			fprintf(stdout, "[c]lose - close device\n");
			fprintf(stdout, "[l]ist - list devices\n");

		} else if (!strcmp(cmd, "open") || !strcmp(cmd, "o")) {
			int fd;
			struct device *device;

			fprintf(stdout, "group fd #: ");
			fscanf(stdin, "%d", &fd);

			fprintf(stdout, "device name: ");
			fscanf(stdin, "%s", cmd);

			ret = ioctl(fd, VFIO_GROUP_GET_DEVICE_FD, cmd);
			if (ret < 0) {
				fprintf(stderr, "get device failed (%s)\n",
					strerror(errno));
				return ret;
			}

			device = malloc(sizeof(*device));
			if (!device) {
				fprintf(stderr, "malloc device failed (%s)\n",
					strerror(errno));
				return -1;
			}

			device->fd = ret;
			device->name = strdup(cmd);
			device->next = device_list;
			device_list = device;
			print_device(device);
			return 0;

		} else if (!strcmp(cmd, "close") || !strcmp(cmd, "c")) {
			struct device *device;

			fprintf(stdout, "device name: ");
			fscanf(stdin, "%s", cmd);

			for (device = device_list;
			     device && strcmp(device->name, cmd);
			     device = device->next);

			if (!device) {
				fprintf(stderr, "device not found\n");
				return 0;
			}

			ret = close(device->fd);
			if (ret) {
				fprintf(stderr, "Error closing device (%s)\n",
					strerror(errno));
				return ret;
			}
			
			if (device == device_list)
				device_list = device->next;
			else {
				struct device *prev;

				for (prev = device_list; prev->next != device;
				     prev = prev->next);

				prev->next = device->next;
			}
			free(device->name);
			free(device);
			return 0;

		} else if (!strcmp(cmd, "list") || !strcmp(cmd, "l")) {
			struct device *device;

			for (device = device_list;
			     device; device = device->next)
				print_device(device);

			return 0;
		}
	}
	return 0;
}

void do_iommu()
{

}

int main(int argc, char **argv)
{
	char cmd[256];
	int ret;

	while (1) {
		fprintf(stdout, "command: ");
		fscanf(stdin, "%s", cmd);

		if (!strcmp(cmd, "quit") || !strcmp(cmd, "exit") ||
		    !strcmp(cmd, "q"))
			return 0;

		if (!strcmp(cmd, "help") || !strcmp(cmd, "h")) {
			fprintf(stdout, "[h]elp - this message\n");
			fprintf(stdout, "[p]rint - print group\n");
			fprintf(stdout, "[o]pen - open group\n");
			fprintf(stdout, "[c]lose - close group\n");
			fprintf(stdout, "close[f]d - close fd\n");
			fprintf(stdout, "[m]erge - merge group\n");
			fprintf(stdout, "[u]nmerge - unmerge group\n");
			fprintf(stdout, "[d]evice - device commands\n");
			fprintf(stdout, "[i]ommu - iommu commands\n");
			fprintf(stdout, "[l]ist - list groups\n");

		} else if (!strcmp(cmd, "print") || !strcmp(cmd, "p")) {
			unsigned int number;

			fprintf(stdout, "group #: ");
			fscanf(stdin, "%u", &number);

			print_group(number);

		} else if (!strcmp(cmd, "device") || !strcmp(cmd, "d")) {
			do_device();

		} else if (!strcmp(cmd, "iommu") || !strcmp(cmd, "i")) {
			do_iommu();

		} else if (!strcmp(cmd, "list") || !strcmp(cmd, "l")) {
			struct group *group;

			for (group = group_list; group; group = group->next)
				print_group(group->number);

		} else if (!strcmp(cmd, "open") || !strcmp(cmd, "o")) {
			unsigned int number;
			struct group *group;
			char path[256];

			fprintf(stdout, "group #: ");
			fscanf(stdin, "%u", &number);

			group = malloc(sizeof(*group));
			if (!group) {
				fprintf(stderr, "Failed to alloc group\n");
				return -1;
			}

			snprintf(path, sizeof(path), "/dev/vfio/%u", number);
			group->fd = open(path, O_RDWR);
			if (group->fd < 0) {
				fprintf(stderr, "Failed to open %s (%s)\n",
					path, strerror(errno));
				free(group);
				continue;
			}
			group->number = number;
			group->next = group_list;
			group_list = group;

			print_group(number);

		} else if (!strcmp(cmd, "close") || !strcmp(cmd, "c")) {
			unsigned int number;
			struct group *group;
			int ret;

			fprintf(stdout, "group #: ");
			fscanf(stdin, "%u", &number);

			for (group = group_list;
			     group && group->number != number;
			     group = group->next);

			if (!group) {
				fprintf(stderr, "group not open, open first\n");
				continue;
			}

			ret = close(group->fd);
			if (ret) {
				fprintf(stderr, "close failed (%s)\n",
					strerror(errno));
				continue;
			}

			if (group == group_list)
				group_list = group->next;
			else {
				struct group *prev;

				for (prev = group_list; prev->next != group;
				     prev = prev->next);

				prev->next = group->next;
			}
			free(group);

		} else if (!strcmp(cmd, "closefd") || !strcmp(cmd, "f")) {
			int fd;
			struct group *group;
			int ret;

			fprintf(stdout, "fd #: ");
			fscanf(stdin, "%d", &fd);

			for (group = group_list;
			     group && group->fd != fd;
			     group = group->next);

			if (!group) {
				fprintf(stderr, "group not open, open first\n");
				continue;
			}

			ret = close(group->fd);
			if (ret) {
				fprintf(stderr, "close failed (%s)\n",
					strerror(errno));
				continue;
			}

			if (group == group_list)
				group_list = group->next;
			else {
				struct group *prev;

				for (prev = group_list; prev->next != group;
				     prev = prev->next);

				prev->next = group->next;
			}
			free(group);

		} else if (!strcmp(cmd, "merge") || !strcmp(cmd, "m")) {
			unsigned int numberA, numberB;
			struct group *groupA, *groupB;
			int ret;

			fprintf(stdout, "base group #: ");
			fscanf(stdin, "%u", &numberA);

			for (groupA = group_list;
			     groupA && groupA->number != numberA;
			     groupA = groupA->next);

			if (!groupA) {
				fprintf(stderr, "group not open, open first\n");
				continue;
			}

			fprintf(stdout, "merge group #: ");
			fscanf(stdin, "%u", &numberB);

			for (groupB = group_list;
			     groupB && groupB->number != numberB;
			     groupB = groupB->next);

			if (!groupB) {
				fprintf(stderr, "group not open, open first\n");
				continue;
			}

			ret = ioctl(groupA->fd, VFIO_GROUP_MERGE, &groupB->fd);
			if (ret) {
				fprintf(stderr, "group merge failed (%s)\n",
					strerror(errno));
					continue;
			}

			print_group(numberA);
			print_group(numberB);

		} else if (!strcmp(cmd, "unmerge") || !strcmp(cmd, "u")) {
			unsigned int numberA, numberB;
			struct group *groupA, *groupB;
			int ret;

			fprintf(stdout, "base group #: ");
			fscanf(stdin, "%u", &numberA);

			for (groupA = group_list;
			     groupA && groupA->number != numberA;
			     groupA = groupA->next);

			if (!groupA) {
				fprintf(stderr, "group not open, open first\n");
				continue;
			}

			fprintf(stdout, "unmerge group #: ");
			fscanf(stdin, "%u", &numberB);

			for (groupB = group_list;
			     groupB && groupB->number != numberB;
			     groupB = groupB->next);

			if (!groupB) {
				fprintf(stderr, "group not open, open first\n");
				continue;
			}

			ret = ioctl(groupA->fd,
				    VFIO_GROUP_UNMERGE, &groupB->fd);
			if (ret) {
				fprintf(stderr, "group unmerge failed (%s)\n",
					strerror(errno));
					continue;
			}

			print_group(numberA);
			print_group(numberB);
		}
	}
}
