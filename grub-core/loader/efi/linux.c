/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2014 Free Software Foundation, Inc.
 *
 *  GRUB is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  GRUB is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with GRUB.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <grub/err.h>
#include <grub/mm.h>
#include <grub/types.h>
#include <grub/cpu/linux.h>
#include <grub/efi/efi.h>
#include <grub/efi/pe32.h>
#include <grub/efi/linux.h>

#include <grub/video.h>
#include <grub/gfxterm.h>
#include <grub/bitmap.h>
#include <grub/bitmap_scale.h>

#define SHIM_LOCK_GUID \
 { 0x605dab50, 0xe046, 0x4300, {0xab, 0xb6, 0x3d, 0xd8, 0x10, 0xdd, 0x8b, 0x23} }

struct grub_efi_shim_lock
{
  grub_efi_status_t (*verify) (void *buffer, grub_uint32_t size);
};
typedef struct grub_efi_shim_lock grub_efi_shim_lock_t;

grub_efi_boolean_t
grub_linuxefi_secure_validate (void *data, grub_uint32_t size)
{
  grub_efi_guid_t guid = SHIM_LOCK_GUID;
  grub_efi_shim_lock_t *shim_lock;

  shim_lock = grub_efi_locate_protocol(&guid, NULL);

  if (!shim_lock || shim_lock->verify(data, size) != GRUB_EFI_SUCCESS) {
    /* The SHIM_LOCK protocol is missing or verification failed. */
    return 0;
  }

  return 1;
}

typedef void (*handover_func) (void *, grub_efi_system_table_t *, void *);

grub_err_t
grub_efi_linux_boot (void *kernel_addr, grub_off_t offset,
		     void *kernel_params)
{
  handover_func hf;

  hf = (handover_func)((char *)kernel_addr + offset);
  hf (grub_efi_image_handle, grub_efi_system_table, kernel_params);

  return GRUB_ERR_BUG;
}

grub_err_t
grub_gfxterm_warning_image (const char *filename)
{
	/* Check that we have video adapter active.  */
	if (grub_video_get_info(NULL) != GRUB_ERR_NONE)
		return grub_errno;

	/* Destroy existing background bitmap if loaded.  */
	if (grub_gfxterm_background.bitmap)
	{
		grub_video_bitmap_destroy (grub_gfxterm_background.bitmap);
		grub_gfxterm_background.bitmap = 0;
		grub_gfxterm_background.blend_text_bg = 0;

		/* Mark whole screen as dirty.  */
		grub_gfxterm_schedule_repaint ();
	}

	/* Try to load new one.  */
	grub_video_bitmap_load (&grub_gfxterm_background.bitmap, filename);
	if (grub_errno != GRUB_ERR_NONE)
		return grub_errno;

	unsigned int width, height;
	grub_gfxterm_get_dimensions (&width, &height);
	if (width != grub_video_bitmap_get_width (grub_gfxterm_background.bitmap)
	|| height != grub_video_bitmap_get_height (grub_gfxterm_background.bitmap))
	{
		struct grub_video_bitmap *scaled_bitmap;

		grub_video_bitmap_create_scaled (&scaled_bitmap,
										  width,
										  height,
										  grub_gfxterm_background.bitmap,
										  GRUB_VIDEO_BITMAP_SCALE_METHOD_BEST);
		if (grub_errno == GRUB_ERR_NONE)
		{
			/* Replace the original bitmap with the scaled one.  */
			grub_video_bitmap_destroy (grub_gfxterm_background.bitmap);
			grub_gfxterm_background.bitmap = scaled_bitmap;
		}
	}

	/* If bitmap was loaded correctly, display it.  */
	if (grub_gfxterm_background.bitmap)
	{
		grub_gfxterm_background.blend_text_bg = 1;

		/* Mark whole screen as dirty.  */
		grub_gfxterm_schedule_repaint ();
	}

	/* All was ok.  */
	grub_errno = GRUB_ERR_NONE;
	return grub_errno;
}

