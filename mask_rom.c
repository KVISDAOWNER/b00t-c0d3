/*
EARLY DRAFT
Not compiled or otherwise tested for ANSI C compliance

Written based on:
sw/device/rom_ext/docs/manifest.md
sw/device/mask_rom/mask_rom.c
sw/device/mask_rom/docs/index.md
doc/security/specs/secure_boot/index.md

*/

//Represents a public key
typedef struct pub_key_t{
    int key;
    //something else
} pub_key_t;

//Struct representing rom_ext_manifest
typedef struct rom_ext_manifest_t{
    int identifier;
    
    int image_code[];
    
    //address of entry point
    //note: not part of the doc on the rom_ext_manifest, but included based on code seen in mask_rom.c
    int entry_point;
    
    int signature;
    
    //public part of signature key
    pub_key_t pub_signature_key;
} rom_ext_manifest_t;


//Returned by rom_ext_manifests_to_try
typedef struct rom_exts_manifests_t{
    int size;
    rom_ext_manifest rom_exts_mfs[];
} rom_exts_manifests_t;


//Represents boot policy
typedef struct boot_policy_t{
    int identifier;
    
    //which rom_ext_slot to boot
    int rom_ext_slot;
    
    //what to do if ROM Ext validation fails
    void (*fail) (rom_ext_manifest_t);
    
    //what to do before jumping to rom ext upon successful validation of rom ext.
    //Note: not called at the moment.
    void (*success) (params);
    
} boot_policy_t;

typedef void(rom_ext_boot_func)(void); // Function type used to define function pointer to the entry of the ROM_EXT stage.


void mask_rom_boot(void)
{
    boot_policy_t boot_policy = read_boot_policy();
    
    rom_exts_manifests_t rom_exts_to_try = rom_ext_manifests_to_try(boot_policy);
    
    //Måske step 2.iii
    for (int i = 0; i < rom_exts_to_try.size; i++)
    {
        rom_ext_manifest_t current_rom_ext_manifest = rom_exts_to_try.rom_exts_mfs[i];

        if (!check_rom_ext_manifest(current_rom_ext_manifest)) {
          continue;
        }
        
        //Step 2.iii.b
        pub_key_t rom_ext_pub_key = read_pub_key(current_rom_ext_manifest); 
        
        //Step 2.iii.b
        if (!check_pub_key_valid(rom_ext_pub_key)) {
            continue;
        }
        
        //Step 2.iii.b
        if (!verify_rom_ext_signature(rom_ext_pub_key, current_rom_ext_manifest)) {
            continue;
        }
        
        //Step 2.iii.d
        pmp_unlock_rom_ext();
        
        //Step 2.iii.e
        if (!final_jump_to_rom_ext(current_rom_ext_manifest)) {
            //Step 2.iv            
            boot_failed(boot_policy, current_rom_ext_manifest);
        }
    } // End for
    
    //Step 2.iv
    boot_failed(boot_policy, rom_exts_to_try.rom_exts_mfs[rom_exts_to_try.size - 1]);

}

extern int[] READ_FLASH(int start, int end);

boot_policy_t read_boot_policy()
{
    int data[] = READ_FLASH(0x0000, 0x1000); // 0 - 4096
    
    boot_policy_t boot_policy;
    
    memcpy(&boot_policy.identifier, data, 512); 
    memcpy(&boot_policy.rom_ext_slot, data+(100/sizeof(int)), 2560); 
    memcpy(&boot_policy.success, data+(800/sizeof(int)), 512); 
    memcpy(&boot_policy.fail, data+(900/sizeof(int)), 512);
    
    return boot_policy;
}

rom_exts_manifests_t rom_ext_manifests_to_try(boot_policy_t boot_policy){}

pub_key_t read_pub_key(rom_ext_manifest_t current_rom_ext_manifest){
    return current_rom_ext_manifest.pub_signature_key;
}

extern int check_pub_key_valid(pub_key_t rom_ext_pub_key); // returns a boolean value

extern int HMAC(pub_key_t pub_key, rom_ext_manifest_t manifest);

int verify_rom_ext_signature(pub_key_t rom_ext_pub_key, rom_ext_manifest_t current_rom_ext_manifest){
    return HMAC(rom_ext_pub_key, current_rom_ext_manifest); //0 or 1
}

extern void WRITE_PMP_REGION(uint8_t reg, uint8_t r, uint8_t w, uint8_t e, uint8_t l);
void pmp_unlock_rom_ext(){
    //Read, Execute, Locked the address space of the ROM extension image
    WRITE_PMP_REGION(0,         1,          0,          1,          1       );
    //               Region     Read        Write       Execute     Locked 
}

int final_jump_to_rom_ext(rom_ext_manifest_t current_rom_ext_manifest){ // Returns a boolean value.
    //Execute rom ext code step 2.iii.e
    rom_ext_boot_func *rom_ext_entry = (rom_ext_boot_func*) current_rom_ext_manifest.entry_point;
    
    rom_ext_entry();
    
    //if rom_ext returns, we should return false 
    //and execute step 2.iv.
    return 0; 
}

void boot_failed(boot_policy_t boot_policy, rom_ext_manifest_t current_rom_ext_manifest){
    boot_policy.failure(current_rom_ext_manifest);
}
