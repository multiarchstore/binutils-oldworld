#include "sysdep.h"
#include "opcode/loongarch.h"

int
is_unsigned (const char *c_str)
{
  if (c_str[0] == '0' && (c_str[1] == 'x' || c_str[1] == 'X'))
    {
      c_str += 2;
      while (('a' <= *c_str && *c_str <= 'f')
	     || ('A' <= *c_str && *c_str <= 'F')
	     || ('0' <= *c_str && *c_str <= '9'))
	c_str++;
    }
  else if (*c_str == '\0')
    return 0;
  else
    while ('0' <= *c_str && *c_str <= '9')
      c_str++;
  return *c_str == '\0';
}

int
is_signed (const char *c_str)
{
  return *c_str == '-' ? is_unsigned (c_str + 1) : is_unsigned (c_str);
}

int
loongarch_get_bit_field_width (const char *bit_field, char **end)
{
  int width = 0;
  char has_specify = 0, *bit_field_1 = (char *) bit_field;
  if (bit_field_1 && *bit_field_1 != '\0')
    while (1)
      {
	strtol (bit_field_1, &bit_field_1, 10);

	if (*bit_field_1 != ':')
	  break;
	bit_field_1++;

	width += strtol (bit_field_1, &bit_field_1, 10);
	has_specify = 1;

	if (*bit_field_1 != '|')
	  break;
	bit_field_1++;
      }
  if (end)
    *end = bit_field_1;
  return has_specify ? width : -1;
}

int32_t
loongarch_decode_imm (const char *bit_field, insn_t insn, int si)
{
  int32_t ret = 0;
  uint32_t t;
  int len = 0, width, b_start;
  char *bit_field_1 = (char *) bit_field;
  while (1)
    {
      b_start = strtol (bit_field_1, &bit_field_1, 10);
      if (*bit_field_1 != ':')
	break;
      width = strtol (bit_field_1 + 1, &bit_field_1, 10);
      len += width;

      t = insn;
      t <<= sizeof (t) * 8 - width - b_start;
      t >>= sizeof (t) * 8 - width;
      ret <<= width;
      ret |= t;

      if (*bit_field_1 != '|')
	break;
      bit_field_1++;
    }

  if (*bit_field_1 == '<' && *(++bit_field_1) == '<')
    {
      width = atoi(bit_field_1 + 1);
      ret <<= width;
      len += width;
    }
  else if (*bit_field_1 == '+')
    ret += atoi(bit_field_1 + 1);

  if (si)
    {
      ret <<= sizeof (ret) * 8 - len;
      ret >>= sizeof (ret) * 8 - len;
    }
  return ret;
}

static insn_t
loongarch_encode_imm (const char *bit_field, int32_t imm)
{
  char *bit_field_1 = (char *) bit_field;
  char *t = bit_field_1;
  int width, b_start;
  insn_t ret = 0, i;

  width = loongarch_get_bit_field_width (t, &t);
  if (width == -1)
    return ret;

  if (*t == '<' && *(++t) == '<')
    width += atoi (t + 1);
  else if (*t == '+')
    imm -= atoi (t + 1);

  imm <<= sizeof (imm) * 8 - width;
  while (1)
    {
      b_start = strtol (bit_field_1, &bit_field_1, 10);
      if (*bit_field_1 != ':')
	break;
      width = strtol (bit_field_1 + 1, &bit_field_1, 10);
      i = imm;
      i >>= sizeof (i) * 8 - width;
      i <<= b_start;
      ret |= i;
      imm <<= width;

      if (*bit_field_1 != '|')
	break;
      bit_field_1++;
    }
  return ret;
}

/* parse such FORMAT
     ""
     "u"
     "v0:5,r5:5,s10:10<<2"
     "r0:5,r5:5,r10:5,u15:2+1"
     "r,r,u0:5+32,u0:5+1"
*/
static int
loongarch_parse_format (const char *format,
			char *esc1s, char *esc2s, const char **bit_fields)
{
  size_t arg_num = 0;

  if (*format == '\0')
    goto end;

  while (1)
    {
      /*        esc1    esc2
	 for "[a-zA-Z][a-zA-Z]?" */
      if (('a' <= *format && *format <= 'z')
	  || ('A' <= *format && *format <= 'Z'))
	{
	  *esc1s++ = *format++;
	  if (('a' <= *format && *format <= 'z')
	      || ('A' <= *format && *format <= 'Z'))
	    *esc2s++ = *format++;
	  else
	    *esc2s++ = '\0';
	}
      else
	return -1;

      arg_num++;
      if (MAX_ARG_NUM_PLUS_2 - 2 < arg_num)
	/* need larger MAX_ARG_NUM_PLUS_2 */
	return -1;

      *bit_fields++ = format;

      if ('0' <= *format && *format <= '9')
	{
	  /* for "[0-9]+:[0-9]+(\|[0-9]+:[0-9]+)*" */
	  while (1)
	    {
	      while ('0' <= *format && *format <= '9')
		format++;

	      if (*format != ':')
		return -1;
	      format++;

	      if (!('0' <= *format && *format <= '9'))
		return -1;
	      while ('0' <= *format && *format <= '9')
		format++;

	      if (*format != '|')
		break;
	      format++;
	    }

	  /* for "((\+|<<)[1-9][0-9]*)?" */
	  do
	    {
	      if (*format == '+')
		format++;
	      else if (format[0] == '<' && format[1] == '<')
		format += 2;
	      else
		break;

	      if (!('1' <= *format && *format <= '9'))
		return -1;
	      while ('0' <= *format && *format <= '9')
		format++;
	    }
	  while (0);
	}

      if (*format == ',')
	format++;
      else if (*format == '\0')
	break;
      else
	return -1;
    }

end:
  *esc1s = '\0';
  return 0;
}

size_t
loongarch_split_args_by_comma (char *args, const char * arg_strs[])
{
  size_t num = 0;

  if (*args)
    arg_strs[num++] = args;
  for (; *args; args++)
    if (*args == ',')
      {
	if (MAX_ARG_NUM_PLUS_2 - 1 == num)
	  break;
	else
	  *args = '\0', arg_strs[num++] = args + 1;
      }
  arg_strs[num] = NULL;
  return num;
}

char *
loongarch_cat_splited_strs (const char *arg_strs[])
{
  char *ret;
  size_t n, l;

  for (l = 0, n = 0; arg_strs[n]; n++)
    l += strlen (arg_strs[n]);
  ret = malloc (l + n + 1);
  ret[0] = '\0';
  if (0 < n)
    strcat (ret, arg_strs[0]);
  for (l = 1; l < n; l++)
    strcat (ret, ","), strcat (ret, arg_strs[l]);
  return ret;
}

insn_t
loongarch_foreach_args (const char *format, const char *arg_strs[],
			int32_t (*helper) (char esc1, char esc2,
					   const char *bit_field,
					   const char *arg, void *context),
			void *context)
{
  char esc1s[MAX_ARG_NUM_PLUS_2 - 1], esc2s[MAX_ARG_NUM_PLUS_2 - 1];
  const char *bit_fields[MAX_ARG_NUM_PLUS_2 - 1];
  size_t i;
  insn_t ret = 0;
  int ok;

  ok = loongarch_parse_format (format, esc1s, esc2s, bit_fields) == 0;

  /* make sure the num of actual args is equal to the num of escape */
  for (i = 0; esc1s[i] && arg_strs[i]; i++);
  ok = ok && !esc1s[i] && !arg_strs[i];

  if (ok && helper)
    {
      for (i = 0; arg_strs[i]; i++)
	ret |= loongarch_encode_imm (bit_fields[i],
		 helper (esc1s[i], esc2s[i], bit_fields[i],
			 arg_strs[i], context));
      ret |= helper ('\0', '\0', NULL, NULL, context);
    }

  return ret;
}

int
loongarch_check_format (const char *format)
{
  char esc1s[MAX_ARG_NUM_PLUS_2 - 1], esc2s[MAX_ARG_NUM_PLUS_2 - 1];
  const char *bit_fields[MAX_ARG_NUM_PLUS_2 - 1];

  if (!format)
    return -1;

  return loongarch_parse_format (format, esc1s, esc2s, bit_fields);
}

int
loongarch_check_macro (const char *format, const char *macro)
{
  int num_of_args;
  char esc1s[MAX_ARG_NUM_PLUS_2 - 1], esc2s[MAX_ARG_NUM_PLUS_2 - 1];
  const char *bit_fields[MAX_ARG_NUM_PLUS_2 - 1];

  if (!format || !macro
      || loongarch_parse_format (format, esc1s, esc2s, bit_fields) != 0)
    return -1;

  for (num_of_args = 0; esc1s[num_of_args]; num_of_args++);

  for (; macro[0]; macro++)
    if (macro[0] == '%')
      {
	macro++;
	if ('1' <= macro[0] && macro[0] <= '9')
	  {
	    if (num_of_args < macro[0] - '0')
	      /* out of args num */
	      return -1;
	  }
	else if (macro[0] == 'f');
	else if (macro[0] == '%');
	else
	  return -1;
      }
  return 0;
}

static const char *
I (char esc_ch1 ATTRIBUTE_UNUSED,
   char esc_ch2 ATTRIBUTE_UNUSED,
   const char *c_str)
{
  return c_str;
}

char *
loongarch_expand_macro_with_format_map (const char *format, const char *macro,
					const char * const arg_strs[],
					const char * (*map) (
					  char esc1, char esc2,
					  const char *arg),
					char * (*helper) (
					  const char * const arg_strs[],
					  void *context),
					void *context, size_t len_str)
{
  char esc1s[MAX_ARG_NUM_PLUS_2 - 1], esc2s[MAX_ARG_NUM_PLUS_2 - 1];
  const char *bit_fields[MAX_ARG_NUM_PLUS_2 - 1];
  const char *src;
  char *dest;

  /*The expanded macro character length does not exceed 1000, and number of
   * label is 6 at most in the expanded macro. The len_str is the length of
   * str.
   */
  char *buffer = (char *) malloc(1000 + 6 * len_str);

  if (format)
    loongarch_parse_format (format, esc1s, esc2s, bit_fields);

  src = macro;
  dest = buffer;

  while (*src)
    if (*src == '%')
      {
	src++;
	if ('1' <= *src && *src <= '9')
	  {
	    size_t i = *src - '1';
	    const char *t = map (esc1s[i], esc2s[i], arg_strs[i]);
	    while (*t)
	      *dest++ = *t++;
	  }
	else if (*src == '%')
	  *dest++ = '%';
	else if (*src == 'f' && helper)
	  {
	    char *b, *t;
	    t = b = (*helper) (arg_strs, context);
	    if (b)
	      {
		while (*t)
		  *dest++ = *t++;
		free (b);
	      }
	  }
	src++;
      }
    else
      *dest++ = *src++;

  *dest = '\0';
  return buffer;
}

char *
loongarch_expand_macro (const char *macro, const char * const arg_strs[],
			char * (*helper) (const char * const arg_strs[],
					  void *context),
			void *context, size_t len_str)
{
  return loongarch_expand_macro_with_format_map
	   (NULL, macro, arg_strs, I, helper, context, len_str);
}

size_t
loongarch_bits_imm_needed (int64_t imm, int si)
{
  size_t ret;
  if (si)
    {
      if (imm < 0)
	{
	  for (ret = 0; imm < 0; imm <<= 1, ret++);
	  ret = 64 - ret + 1;
	}
      else
	ret = loongarch_bits_imm_needed (imm, 0) + 1;
    }
  else
    {
      uint64_t t = imm;
      for (ret = 0; t; t >>= 1, ret++);
    }
  return ret;
}

void
loongarch_eliminate_adjacent_repeat_char (char *dest, char c)
{
  if (c == '\0')
    return;
  char *src = dest;
  while (*dest)
    {
      while (src[0] == c && src[0] == src[1])
	src++;
      *dest++ = *src++;
    }
}
