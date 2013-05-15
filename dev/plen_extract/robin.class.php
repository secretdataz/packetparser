<?php
/*
RObin.php

This file creates the RObin class, which is used to
apply modifications to the Ragnarok Online client.

*/

class RObin
{
    public /*protected*/ $exe = "";
    public /*protected*/ $size = 0;
    public $dif = array();
    public $xDiff = array(); //Contains all patches and patch groups
    public $xPatch = null; // Current xPatch
    public $xmlWriter = null;
    
    private $PEHeader = null;
    private $image_base = 0;
    private $sections;
    private $client_date = 0;
    private $crc = 0;
    public $themida = false;
    
    // Loads file from $path
    public function load($path,$debug=false)
    {
        $file = file_get_contents($path);
        if ($file === false) {
            return false;
        }
        $this->crc = crc32($file);
        $this->exe = $file;
        $this->size = strlen($file);
        
        $this->PEHeader = $this->match("\x50\x45\x00\x00");
        if($debug) echo "PE Header\t".dechex($this->PEHeader)."h\n";
        
        // If the loaded file isn't a valid PE file, then it's not necessary to continue
        // with the diff process anyway, so just die~ >:)
        if($this->PEHeader === false)
            die("Invalid PE file used!\n");
            
        $this->image_base = $this->read($this->PEHeader + 0x34, 4, "V");
        if($debug) echo "Image Base\t".dechex($this->image_base)."h\n";
        
        $date = $this->read($this->PEHeader+8, 4, 'V');
        $this->client_date = date('Y', $date) * 10000 + date('m', $date) * 100 + date('d', $date);
        if($debug) echo "Client Date\t".$this->client_date."\n";
        
        if($debug) echo "\nName\tvSize\tvOffset\trSize\trOffset\tvrDiff\n";
        if($debug) echo "----\t-----\t-------\t-----\t-------\t------\n";
        // Get section information
        $sectionCount = $this->read($this->PEHeader + 0x6, 2, "S");
		$sectionInfo = array();
        for($i = 0, $curSection = $this->PEHeader + 0x18 + 0x60 + 0x10 * 0x8; $i < $sectionCount; $i++) {
            // http://www.microsoft.com/whdc/system/platform/firmware/PECOFFdwn.mspx
            $sectionInfo['name'] = $this->read($curSection, 8);
            // Also: There's also possibility that a new inserted section name could contain some trash bytes after
            // the zero terminator. So get rid of them..
            $sectionInfo['name']          = trim($sectionInfo['name']);
            if(!$sectionInfo['name']){
                $sectionInfo['name'] = "sect_".$i;
                $this->themida = true;
            }

            $sectionInfo['vSize']         = $this->read($curSection+8+0*4, 4, "V");
            $sectionInfo['vOffset']       = $this->read($curSection+8+1*4, 4, "V");
            $sectionInfo['vEnd']          = $sectionInfo['vOffset'] + $sectionInfo['vSize'];
            $sectionInfo['rSize']         = $this->read($curSection+8+2*4, 4, "V");
            $sectionInfo['rOffset']       = $this->read($curSection+8+3*4, 4, "V");
            $sectionInfo['rEnd']          = $sectionInfo['rOffset'] + $sectionInfo['rSize'];
            $sectionInfo['vrDiff']        = $sectionInfo['vOffset'] - $sectionInfo['rOffset'];
            // This is used to indicate if code has been placed after vEnd
            $sectionInfo['align']         = 0;
            $tab = "\t";
            if($debug) 
            echo  $sectionInfo['name'] . "\t"
                . dechex($sectionInfo['vSize']) . "\t"
                . dechex($sectionInfo['vOffset']) . "\t"
                . dechex($sectionInfo['rSize']) . "\t"
                . dechex($sectionInfo['rOffset']) . "\t"
                . dechex($sectionInfo['vrDiff']) . "\n";
            // Convert to object for easier access
            // E.g: $exe->getSection(".rdata")->rOffset...
            $this->sections[$sectionInfo['name']] = new stdClass();
            if(is_array($sectionInfo) && count($sectionInfo) > 0) {
                foreach($sectionInfo as $name => $value) {
                    if (!empty($name))
                        $this->sections[$sectionInfo['name']]->$name = $value;
                }
            }

            $curSection += 0x28;
        }

        //print_r($this->sections);
        //die();
        // Prepare XMLWriter for xDiff
        $this->xmlWriter = new XMLWriter();
        $this->xmlWriter->openMemory();
        $this->xmlWriter->setIndent(true);
        $this->xmlWriter->setIndentString("\t");
				$this->xmlWriter->startDocument('1.0', 'ISO-8859-1');
        $this->xmlWriter->startElement('diff');
        
        $this->xmlWriter->startElement('exe');
        $this->xmlWriter->writeElement('builddate', $date);
        $this->xmlWriter->writeElement('filename', basename($path));
        $this->xmlWriter->writeElement('crc', $this->crc);
        $this->xmlWriter->writeElement('type', 'RE');
        $this->xmlWriter->endElement(); // exe
        
        $this->xmlWriter->startElement('info');
        $this->xmlWriter->writeElement('name', '[ '.substr($this->client_date,0,4) . '-' . substr($this->client_date,4,2) . '-' . substr($this->client_date,6,2) . ' kRO ]');
        $this->xmlWriter->writeElement('author', 'DiffTeam');
        $this->xmlWriter->writeElement('version', '1.0');
        $this->xmlWriter->writeElement('releasedate', 'now');
        $this->xmlWriter->endElement(); // info
        
        return true;
    }

    // Reads $size bytes starting at $offset, might format the return using
    // $format, if provided. (see http://www.php.net/pack for more details)
    // Returns raw data if no format specified, a single variable (like an
    // integer or a float) if format only contains one, or an array with the
    // unpack()'ed data.
    public function read($offset, $size, $format = null)
    {
        if (($offset >= $this->size) || ($size < 1)) {
            return false;
        }
        $data = substr($this->exe, $offset, $size);
        if (strlen($data) != $size) {
            // if read size was not $size
            echo bin2hex($data) . "\n";
            return false;
        }
        if (is_string($format)) {
            // If $format is a string, it tries to unpack()
            $data = unpack($format, $data);
            if ($data === false) {
                // Bad format
                return false;
            }
            // Little hack to make code simpler when you want to read only one
            // type of data, like reading a single integer:
            // $this->read($offset, $size, "I")
            // It'll return only the integer, instead of an array of only 1 position with it.
            if ((count($data) == 1) && (isset($data[1]))) {
                $data = $data[1];
            }
        }
        return $data;
    }
    
    // Searches for $pattern (using $wildcard as wildcard), starting at $start, and
    // stopping at $finish (if omitted, it'll search until the end of the file). Returns
    // the first offset it matches, or false if none matched.
    public function match($pattern, $wildcard = "", $start = null, $finish = null)
    {
        $length = strlen($pattern);
        $start = (is_null($start) || ($start <= 0) ? 0 : $start);
        $finish = (is_null($finish) || ($finish > $this->size) ? $this->size : $finish);
        if (($length < 1) || ($start >= $this->size-$length) || ($finish <= $start)) {
            return false;
        }
        $offset = $start;
        // Is there a wildcard?
        if (strlen($wildcard) == 1) {
            // Remove wildcards at the ending of the pattern
            while ($pattern[strlen($pattern) - 1] == $wildcard) {
                $pattern = substr($pattern, 0, strlen($pattern) - 1);
            }
            // Check if wildcard appears in the pattern
            $wpos = strpos($pattern, $wildcard);
            if ($wpos === false) {
                // If not... then we don't need it
                $wildcard = "";
            }
        }
        // Check to see if there's a wildcard
        if (strlen($wildcard) == 1) {
            // If there's a wildcard...
            // First separate it in pieces (offset and value/strlen)
            $exploded = explode($wildcard, $pattern);
            $offset = 0;
            $pieces = array();
            foreach ($exploded as $key => $value)
            {
                if (empty($value) === false)
                {
                    if ($key != 0)
                    {
                        $pieces[$offset] = array($value, strlen($value));
                    }
                    else
                    {
                        $partial = $value;
                    }
                    $offset += strlen($value);
                }
                $offset++;
            }
            
            // Then search for the first part and try to match the rest
            for ($i = strpos($this->exe, $partial, $start); ($i !== false) && ($i < $finish); $i = strpos($this->exe, $partial, $i + 1))
            {
                foreach ($pieces as $offset => $value)
                {
                    if (substr_compare($this->exe, $value[0], $i + $offset, $value[1]) != 0)
                    {
                        continue 2;
                    }
                }
                return $i;
            }
        } else {
            // If not, ordinary strpos() can do it
            $i = strpos($this->exe, $pattern, $start);
            return ($i >= $finish ? false : $i);
        }
        return false;
    }
    
    // Does the same as match(), but it returns an array
    // of all the matching offsets (might be empty)
    public function matches($pattern, $wildcard = "", $start = null, $finish = null)
    {
        $offsets = array();
        $offset = $start;
        while ($offset = $this->match($pattern, $wildcard, $offset + strlen($pattern), $finish)) {
            $offsets[] = $offset;
        }
        if(sizeof($offsets) > 0)
            return $offsets;
        return false;
    }
    
    // Returns an offset where there are $size null bytes, searching
    // on the space after .text section ends and before .rdata begins.
    //
    // Shinryo: It is fatal to place code in free space where
    // it isn't clear if this space is used by the executable.
    // The only place that is safe to use is the one left empty 
    // and filled with zeroes/paddings by the compiler.
    // Whatever is placed after rOffset+vSize, it doesn't matter, because
    // the executable (if not already modified) won't access those data.
    public function zeroed($size, $search_section = ".text")
    {
        $zero = false;
        if($search_section === false) {
          foreach ($this->sections as $section) {
            if(($section->rSize - $section->vSize - $section->align) >= $size) {
              $zero = $section->rOffset + $section->vSize + $section->align;
              break;
            }
          }
        } else {
          $section = $this->getSection($search_section);
          if($section !== false && ($section->rSize - $section->vSize - $section->align) >= $size) {
              $zero = $section->rOffset + $section->vSize + $section->align;
          }
        }
        
        return $zero;
    }
    
    // It was meant to be used for patches that add extra code, where it would
    // replace null bytes (checking if they were really null). Works like replace().
    // should be modified to change the $src to stop conflicting free space
    public function insert($code, $offset)
    {
        global $src;
        $length = strlen($code);
        if ($length < 1) {
            return false;
        }
        for ($i = 0; $i < $length; $i++) {
            if ($this->exe[$offset + $i] != $code[$i]) {
                $poffset = strtoupper(dechex($offset + $i));
                // output values in hex when patcher supports it
                // $pvalue1 = str_pad(strtoupper(dechex(ord($this->exe[$offset + $i]))),2,"0", STR_PAD_LEFT);
                // $pvalue2 = str_pad(strtoupper(dechex(ord($code[$i]))),2,"0", STR_PAD_LEFT);
                $pvalue1 = ord($this->exe[$offset + $i]);
                $pvalue2 = ord($code[$i]);
                //$this->dif[] = $poffset.":".$pvalue1.":".$pvalue2;
                $change = new xPatchChange();
                $change->setType(XTYPE_BYTE);
                $change->setOffset($offset + $i);
                $change->setOld($pvalue1);
                $change->setNew($pvalue2);
                $this->xPatch->addChange($change);
            }
            $this->exe[$offset + $i] = $code[$i];
            
            // Shinryo: $this->exe is a reference to $src from now on.
            //$src->exe[$offset + $i] = $code[$i];      
        }
        // "Fake" valid range for the new inserted code
        // to prevent overlapping with other diffs
        $section = $this->RawOffset2Section($offset);
        $section->align += $length;
        
        return true;
    }
    
    // Replaces stuff starting with a base offset of $offset. $replace is an array
    // Where the key (index) tells the relative offset, and the value is the data
    // that will replace existing data.
    // For instance:
    // replace(400, array(4 => "\x00", 2 => "\xAB"))
    // Replaces the byte at 404 (400 + 4) with a null (x00) byte;
    // Replaces the byte at 402 (400 + 2) with a xAB byte.
    public function replace($offset, $replace)
    {
        foreach ($replace as $pos => $value) {
						if (substr($value,0,1) == '$')// input variable (xDiff)    
						{
							echo 'input: '.$value. " : ";
						  $change = new xPatchChange();
	            $change->setType(XTYPE_BYTE);
	            $change->setOffset($offset + $pos);
	            $change->setOld(ord($this->exe[$offset + $pos]));
	            $change->setNew($value);
	            $this->xPatch->addChange($change); 
						} else
	            for ($i = 0; $i < strlen($value); $i++) {
	                if ($this->exe[$offset + $pos + $i] != $value[$i]) {
	                    $poffset = strtoupper(dechex($offset + $pos + $i));
	                    // output values in hex when patcher supports it
	                    // $pvalue1 = str_pad(strtoupper(dechex(ord($this->exe[$offset + $pos + $i]))),2,"0", STR_PAD_LEFT);
	                    // $pvalue2 = str_pad(strtoupper(dechex(ord($value[$i]))),2,"0", STR_PAD_LEFT);
	                    $pvalue1 = ord($this->exe[$offset + $pos + $i]);
	                    $pvalue2 = ord($value[$i]);
	                    //$this->dif[] = $poffset.":".$pvalue1.":".$pvalue2;
	                    
			                $change = new xPatchChange();
			                $change->setType(XTYPE_BYTE);
			                $change->setOffset($offset + $pos + $i);
			                $change->setOld($pvalue1);
			                $change->setNew($pvalue2);
			                $this->xPatch->addChange($change);                    
	                }
	                
	                // Shinryo:
	                // I left this here even though it's not really necessary or
	                // is a leftover from DiffGen1. In DiffGen2 nothing relys on changes
	                // made JustInTime in the executable. DiffColor() and DiffAutos()
	                // isn't used anymore, therefore there may be space for further improvements.
	                // $this->exe[$offset + $pos + $i] = $value[$i];
            }
        }
        return true;
    }
    
    // Basically works like replace() but replaces words instead of bytes
    public function replaceWord($offset, $replace)
    {
    	foreach ($replace as $pos => $value)
    	{
    		$old = ord($this->exe{$pos+$offset++})+($this->exe($buf{$pos+$offset})<<8);
    		
    		$change = new xPatchChange();
    		$change->setType(XTYPE_WORD);
    		$change->setOffset($offset-1 + $pos);
    		$change->setOld($old);
    		$change->setNew($value);
    		$this->xPatch->addChange($change);
    	}
    }
    
    // Basically works like replace() but replaces dwords instead of bytes
    public function replaceDword($offset, $replace)
    {
    	foreach ($replace as $pos => $value)
    	{
    		$old = ord($this->exe{$pos+$offset++})+(ord($this->exe{$pos+$offset++})<<8)+(ord($this->exe{$pos+$offset++})<<16)+(ord($this->exe{$pos+$offset})<<24);
    		
    		$change = new xPatchChange();
    		$change->setType(XTYPE_DWORD);
    		$change->setOffset($offset-3 + $pos);
    		$change->setOld($old);
    		$change->setNew($value);
    		$this->xPatch->addChange($change);
    	}
    }  
    
    public function replaceString($offset, $replace)
    {
    	foreach ($replace as $pos => $value)
    	{
    		//$old = ord($this->exe{$offset++})+(ord($this->exe{$offset++})<<8)+(ord($this->exe{$offset++})<<16)+(ord($this->exe{$offset})<<24);
    		$old = '';
    		
    		$change = new xPatchChange();
    		$change->setType(XTYPE_STRING);
    		$change->setOffset($offset + $pos);
    		$change->setOld($old);
    		$change->setNew($value);
    		$this->xPatch->addChange($change);
    	}    	
    }  
    
    public function addInput($name, $type, $op='', $min=null, $max=null)
    {
    	$input = new xPatchInput($name, $type, $op, $min, $max);
    	$this->xPatch->addInput($input);
    }
    
    // Returns an array with the changes made since last diff() call.
    public function diff()
    {
        $diff = $this->dif;
        $this->dif = array();
        return $diff;
    }
    
    // Searchs for $code pattern (using $wildcard) , which should match
    // _exactly_ $count times. Returns the offset (or an array of offsets)
    // if it works, or false if the pattern doesn't match exactly $count times.
    // That means if you pass $count as 2, and it finds the pattern once or
    // 3 times, it'll return false. Also, it searches only in .text section.
    // Please note it's meant to be used for searching for code (machine
    // code the client runs, "assembly"). Use matches() for general search.
    // Change: now passing -1 to $count will make the function return all
    // matches.
    public function code($code, $wildcard, $count = 1)
    {

        if($this->themida)
            $section = $this->getSection("sect_0");
        else
            $section = $this->getSection(".text");

        $offsets = $this->matches($code, $wildcard, $section->rOffset, $section->rOffset + $section->rSize);
        //echo var_dump($offsets);
        if (($count != -1) && (count($offsets) != $count)){
            echo "#code() found ".count($offsets)." matches# ";
            return false;
        }
        if ($offsets == false){
            echo "#code() found no matches# ";
            return false;
        }
        return ($count == 1 ? $offsets[0] : $offsets);
    }
    
    // Searches for string $str in .rdata section of the client (where
    // strings are located). Returns the address (to be used with
    // asm stuff, NOT offset inside the client exe). Returns the
    // address on success, or false on failure.
    public function str($str,$type)
    {
        $tick = microtime(true);
        $iBase = $this->imagebase();

        if($this->themida)
            $section = $this->getSection("sect_0");
        else
            $section = $this->getSection(".rdata");

        $virtual = $section->vOffset - $section->rOffset;
        $offset = $this->match("\x00".$str."\x00", "", $section->rOffset, $section->rOffset + $section->rSize);
        if ($offset === false) {
            return false;
        }
        if($type == "rva")
            return $offset + 1 + $virtual + $iBase;
        if($type == "raw")
            return $offset + 1;
        return false;
    }
    
    // I don't really understand how it works (assembly-wise), but...
    // Searches for a function on .rdata section, and returns the address to be
    // used in asm stuff (call instructions, I guess), or false on failure.
    // Some functions work by just searching for their names ($str = true),
    // others however have to be looked for using numbers ($str = false).
    // Used in both ways on Enable DNS Support patch.
    public function func($func, $str = true)
    {
        $tick = microtime(true);
        $iBase = $this->imagebase();
        
        if($this->themida)
            $section = $this->getSection("sect_0");
        else
            $section = $this->getSection(".rdata");

        $virtual = $section->vOffset - $section->rOffset;
        if ($str) {
            // It has to resolve the name or something... can't remember
            $offset = $this->match($func . "\x00", "", $section->rOffset, $section->rOffset + $section->rSize);
            $code = pack("I", $offset - 2 + $virtual);
        } else {
            $code = $func;
        }
        $offset = $this->match($code, "", $section->rOffset, $section->rOffset + $section->rSize);
        if ($offset === false) {
            return false;
        }
        return $offset + $virtual + $iBase;
    }
    
    // XDIFF
	public function writeDiffFile($filePath)
    {
    	//print_r($this->xDiff);
    	$this->xmlWriter->startElement('patches');
    
    	foreach ($this->xDiff as $p)
    	{
    		if (is_a($p, 'xPatchBase')) //Both xPatch and xPatchGroup implement "writeToXml" :)
    			$p->writeToXml($this->xmlWriter);     		
    	}
    
    	$this->xmlWriter->endElement(); //patches
    	$this->xmlWriter->endElement(); //diff
    	$this->xmlWriter->endDocument();
    	
    	file_put_contents($filePath, $this->xmlWriter->outputMemory(true));
    	$this->xmlWriter->flush();
    	unset($this->xmlWriter);
    }
    
    // Workaround for public access, 'cause they shouldn't be changed outside the class
    public function PEHeader() {return $this->PEHeader;}
    public function imagebase() {return $this->image_base;}
    // Returns the client date
    public function clientdate(){return $this->client_date;}
    
    // Returns the section specified by name
    public function getSection($name)
    {
        if(!isset($this->sections[$name]))
            return false;
            
        return $this->sections[$name];
    }
    
    // Those two functions should be useful for further offset conversions
    public function Raw2Rva($offset)
    {
      if(($section = $this->RawOffset2Section($offset)) !== false)
        return $offset + $section->vOffset - $section->rOffset + $this->image_base;
        
      return false;
    }
    
    public function Rva2Raw($offset)
    {
      if(($section = $this->RvaOffset2Section($offset)) !== false)
        return $offset - $this->image_base - $section->vOffset + $section->rOffset;
          
      return false;
    }
    
    public function RawOffset2Section($offset)
    {
      foreach($this->sections as $section ) {
        if($offset >= $section->rOffset && $offset < ($section->rOffset + $section->rSize)) {
          return $section;
        }
      }
      
      return false;
    }
    
    public function RvaOffset2Section($offset)
    {
      $offset -= $this->image_base;
      foreach($this->sections as $section ) {
        if($offset >= $section->vOffset && $offset < ($section->vOffset + $section->vSize + $section->align + ($section->rSize - $section->vSize))) {
          return $section;
        }
      }
      
      return false;
    }
}
?>