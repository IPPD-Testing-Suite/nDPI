bin_PROGRAMS = fuzz_community_id fuzz_serialization
#Algorithms
bin_PROGRAMS += fuzz_alg_bins fuzz_alg_hll fuzz_alg_hw_rsi_outliers_da fuzz_alg_crc32_md5 fuzz_alg_memmem fuzz_alg_strnstr
#Data structures
bin_PROGRAMS += fuzz_ds_cmsketch

#Common flags
AM_CPPFLAGS = -I $(top_srcdir)/src/include -I $(top_srcdir)/src/lib/third_party/include/ @NDPI_CFLAGS@
AM_LDFLAGS = $(LIBS)
# Use AM_CFLAGS for package flags, never modify or embed user's CFLAGS
AM_CFLAGS = @NDPI_CFLAGS@
AM_CXXFLAGS = @NDPI_CFLAGS@
LDADD = $(top_builddir)/src/lib/libndpi.a $(PCAP_LIB) $(ADDITIONAL_LIBS)
if HAS_FUZZLDFLAGS
AM_CFLAGS += $(LIB_FUZZING_ENGINE)
AM_LDFLAGS += $(LIB_FUZZING_ENGINE)
AM_CXXFLAGS += $(LIB_FUZZING_ENGINE)
endif

# Common linker command template for all fuzz targets
# All fuzz targets need to use CXX as linker (required by libFuzzer)
FUZZ_LINK_COMMAND = $(AM_V_CCLD)$(LIBTOOL) $(AM_V_lt) --silent --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) $(AM_CXXFLAGS) $(CXXFLAGS) \
    $($@_LDFLAGS) @NDPI_LDFLAGS@ $(AM_LDFLAGS) $(LDFLAGS) -o $@

# Define sources and flags for each fuzz target
fuzz_community_id_SOURCES = fuzz_community_id.cpp fuzz_common_code.c
fuzz_community_id_LINK = $(FUZZ_LINK_COMMAND)

fuzz_serialization_SOURCES = fuzz_serialization.cpp fuzz_common_code.c
fuzz_serialization_LINK = $(FUZZ_LINK_COMMAND)

fuzz_alg_bins_SOURCES = fuzz_alg_bins.cpp fuzz_common_code.c
fuzz_alg_bins_LINK = $(FUZZ_LINK_COMMAND)

fuzz_alg_hll_SOURCES = fuzz_alg_hll.cpp fuzz_common_code.c
fuzz_alg_hll_LINK = $(FUZZ_LINK_COMMAND)

fuzz_alg_hw_rsi_outliers_da_SOURCES = fuzz_alg_hw_rsi_outliers_da.cpp fuzz_common_code.c
fuzz_alg_hw_rsi_outliers_da_LINK = $(FUZZ_LINK_COMMAND)

fuzz_alg_crc32_md5_SOURCES = fuzz_alg_crc32_md5.c
fuzz_alg_crc32_md5_LINK = $(FUZZ_LINK_COMMAND)

fuzz_alg_memmem_SOURCES = fuzz_alg_memmem.cpp
fuzz_alg_memmem_LINK = $(FUZZ_LINK_COMMAND)

fuzz_alg_strnstr_SOURCES = fuzz_alg_strnstr.cpp
fuzz_alg_strnstr_LINK = $(FUZZ_LINK_COMMAND)

fuzz_ds_cmsketch_SOURCES = fuzz_ds_cmsketch.cpp fuzz_common_code.c
fuzz_ds_cmsketch_LINK = $(FUZZ_LINK_COMMAND)

# required for Google oss-fuzz
# see https://github.com/google/oss-fuzz/tree/master/projects/ndpi
# Corpus files from seed directories (incremental: only rebuild if source files changed)
files_corpus_fuzz_community_id := $(wildcard $(srcdir)/corpus/fuzz_community_id_seed/*)
fuzz_community_id_seed_corpus.zip: $(files_corpus_fuzz_community_id)
	@zip -q -j $@ $(files_corpus_fuzz_community_id)

files_corpus_fuzz_alg_bins := $(wildcard $(srcdir)/corpus/fuzz_alg_bins_seed/*)
fuzz_alg_bins_seed_corpus.zip: $(files_corpus_fuzz_alg_bins)
	@zip -q -j $@ $(files_corpus_fuzz_alg_bins)

files_corpus_fuzz_alg_hll := $(wildcard $(srcdir)/corpus/fuzz_alg_hll_seed/*)
fuzz_alg_hll_seed_corpus.zip: $(files_corpus_fuzz_alg_hll)
	@zip -q -j $@ $(files_corpus_fuzz_alg_hll)

files_corpus_fuzz_alg_memmem := $(wildcard $(srcdir)/corpus/fuzz_alg_memmem_seed/*)
fuzz_alg_memmem_seed_corpus.zip: $(files_corpus_fuzz_alg_memmem)
	@zip -q -j $@ $(files_corpus_fuzz_alg_memmem)

files_corpus_fuzz_alg_hw_rsi_outliers_da := $(wildcard $(srcdir)/corpus/fuzz_alg_hw_rsi_outliers_da_seed/*)
fuzz_alg_hw_rsi_outliers_da_seed_corpus.zip: $(files_corpus_fuzz_alg_hw_rsi_outliers_da)
	@zip -q -j $@ $(files_corpus_fuzz_alg_hw_rsi_outliers_da)

files_corpus_fuzz_alg_crc32_md5 := $(wildcard $(srcdir)/corpus/fuzz_alg_crc32_md5_seed/*)
fuzz_alg_crc32_md5_seed_corpus.zip: $(files_corpus_fuzz_alg_crc32_md5)
	@zip -q -j $@ $(files_corpus_fuzz_alg_crc32_md5)

files_corpus_fuzz_alg_strnstr := $(wildcard $(srcdir)/corpus/fuzz_alg_strnstr_seed/*)
fuzz_alg_strnstr_seed_corpus.zip: $(files_corpus_fuzz_alg_strnstr)
	@zip -q -j $@ $(files_corpus_fuzz_alg_strnstr)

files_corpus_fuzz_ds_cmsketch := $(wildcard $(srcdir)/corpus/fuzz_ds_cmsketch_seed/*)
fuzz_ds_cmsketch_seed_corpus.zip: $(files_corpus_fuzz_ds_cmsketch)
	@zip -q -j $@ $(files_corpus_fuzz_ds_cmsketch)

files_corpus_fuzz_serialization := $(wildcard $(srcdir)/corpus/fuzz_serialization_seed/*)
fuzz_serialization_seed_corpus.zip: $(files_corpus_fuzz_serialization)
	@zip -q -j $@ $(files_corpus_fuzz_serialization)

# Phony target to build all corpora
.PHONY: corpus
corpus: fuzz_community_id_seed_corpus.zip fuzz_alg_bins_seed_corpus.zip fuzz_alg_hll_seed_corpus.zip fuzz_alg_memmem_seed_corpus.zip fuzz_alg_hw_rsi_outliers_da_seed_corpus.zip fuzz_alg_crc32_md5_seed_corpus.zip fuzz_alg_strnstr_seed_corpus.zip fuzz_ds_cmsketch_seed_corpus.zip fuzz_serialization_seed_corpus.zip
	@echo "All corpus files are up to date"

clean-local:
	$(RM) *.o $(bin_PROGRAMS)
	$(RM) *_seed_corpus.zip
	$(RM) fuzz*.dict
	$(RM) -r .libs .deps

distclean-local:
	$(RM) Makefile

distdir:
	find $(srcdir) -type d | xargs -I'{}' mkdir -p '$(distdir)/{}'
	find $(srcdir) -type f -name '*.c' \
		-o -name '*.am' \
		-o -name '*.h' \
		-o -name '*.cpp' \
		-o -name '*.options' \
		-o -name 'ipv4_addresses.txt' \
		-o -name 'ipv6_addresses.txt' \
		-o -name 'bd_param.txt' \
		-o -name 'splt_param.txt' \
		-o -name 'random_list.list' \
		-o -path '$(srcdir)/dictionary.dict' \
		-o -path '$(srcdir)/corpus/fuzz_community_id_seed/*' \
		-o -path '$(srcdir)/corpus/fuzz_alg_bins_seed/*' \
		-o -path '$(srcdir)/corpus/fuzz_alg_hll_seed/*' \
		-o -path '$(srcdir)/corpus/fuzz_alg_memmem_seed/*' \
		-o -path '$(srcdir)/corpus/fuzz_alg_hw_rsi_outliers_da_seed/*' \
		-o -path '$(srcdir)/corpus/fuzz_alg_crc32_md5_seed/*' \
		-o -path '$(srcdir)/corpus/fuzz_alg_strnstr_seed/*' \
		-o -path '$(srcdir)/corpus/fuzz_ds_cmsketch_seed/*' \
		-o -path '$(srcdir)/corpus/fuzz_serialization_seed/*' | xargs -I'{}' cp -r '{}' '$(distdir)/{}'
	find . -type l -name '*.c' | xargs -I'{}' cp -r '{}' '$(distdir)/{}'

all: corpus
