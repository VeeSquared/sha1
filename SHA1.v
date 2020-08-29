module SHA1_hash (       
	clk,
	nreset,
	start_hash,
	message_addr,
	message_size,
	hash,
	done,
	port_A_clk,
        port_A_data_in,
        port_A_data_out,
        port_A_addr,
        port_A_we
	);

input	clk;
input	nreset;
// Initializes the SHA1_hash module

input	start_hash;
// Tells SHA1_hash to start hashing the given frame

input 	[31:0] message_addr;
// Starting address of the messagetext frame
// i.e., specifies from where SHA1_hash must read the messagetext frame

input	[31:0] message_size;
// Length of the message in bytes

output	[159:0] hash;
// hash results


input   [31:0] port_A_data_out;
// read data from the dpsram (messagetext)

output  [31:0] port_A_data_in;
// write data to the dpsram (ciphertext)

output  [15:0] port_A_addr;
// address of dpsram being read/written

output  port_A_clk;
// clock to dpsram (drive this with the input clk)

output  port_A_we;
// read/write selector for dpsram

output	done; // done is a signal to indicate that hash  is complete

//declarations
reg				state;
reg [31:0]		newMess[0:4];
reg [31:0]		currMess[0:4];
reg [31:0]		currSize;
reg [31:0]		wrd;
reg [31:0]		W[0:15];
reg [31:0]		ktVal;
reg [31:0]		bcdF;
reg [31:0]		tWdVal;
reg [31:0] 		h0 = 32'h67452301;
reg [31:0] 		h1 = 32'hEFCDAB89;
reg [31:0] 		h2 = 32'h98BADCFE;
reg [31:0] 		h3 = 32'h10325476;
reg [31:0] 		h4 = 32'hC3D2E1F0;
reg [15:0]		read_addr;
reg [9:0] 		nbitword = 10'b1000000000;
reg [6:0] 		sbitword = 7'b1000000;
reg [6:0]		cnt3;
reg [1:0]		rrInit;

integer tInt;
integer bitshft=30;
integer thrtwobit=32;
integer btshft=8;

wire [31:0] rdwd;
wire [31:0] size;
wire [31:0]	a0;
wire [31:0] a1;
wire [31:0] a2;
wire [31:0] b0;
wire [31:0] b1;
wire [31:0] b2;
wire [31:0] c0;
wire [31:0] c1;
wire [31:0] c2;
wire [31:0] d0;
wire [31:0] d1;
wire [31:0] d2;
wire [31:0] e0;
wire [31:0] e1;
wire [31:0] e2;
wire [31:0] wSft;
wire [31:0] currLength;
wire [31:0] messLength;
wire [15:0]	rraddr;
wire [9:0]	paddingSize;
wire [6:0]	cnt;
wire [6:0]	cnt2;
wire [6:0]	currW;
wire		rrStp;

//aquired from testbench_v6.v
function [31:0] changeEndian; // transform data from the memory to big-endian form (default: little)
    input [31:0] value;
    changeEndian = {value[7:0], value[15:8], value[23:16], value[31:24]};
endfunction

//Assigns A,B,C,D, and E Values
//(a,b,c,d,e)(0) = current Message Digest
//(a,b,c,d,e)(1) = step4
//(a,b,c,d,e)(2) = step5 append message into 160bit hash
assign a1 = tWdVal; //set a to t value
assign a2 = newMess[0] + a1;
assign a0 = currMess[0];
assign b1 = a0; //set b to a value
assign b2 = newMess[1] + b1;
assign b0 = currMess[1];
assign c1 = (b0<<bitshft)|(b0>>2); //set c to b value shifted 30
assign c2 = newMess[2] + c1;
assign c0 = currMess[2];
assign d1 = c0; //set d to c value
assign d2 = newMess[3] + d1;
assign d0 = currMess[3];
assign e1 = d0; //set e to d value
assign e2 = newMess[4] + e1;
assign e0 = currMess[4];


parameter IDLE = 1'b0;
//parameter READ = 2'b01;
parameter EXE = 1'b1;
//parameter WRITE = 2'b11;

assign port_A_clk = clk;
assign port_A_addr = read_addr;

always@(posedge clk or negedge nreset)
begin
	if(!nreset) //Resets all Values
		begin
			state <= IDLE;
			tInt = 0;
			rrInit <= 2'b0;
			cnt3 <= 7'b0;
			currSize <= 32'b0;

			while(tInt < 5) begin
				currMess[tInt] <= 32'b0;
				newMess[tInt] <= 32'b0;
				tInt = 1 + tInt;
			end
		end
	else
		begin
			case(state)
				IDLE: //Initializes Values
					begin
						if(start_hash)
							begin
								state <= EXE;
								read_addr <= message_addr[15:0];
								rrInit <= 2'b10;
								currSize <= 32'b0;
								//Initializes the Message Digest
								newMess[0] <= h0;
								currMess[0] <= h0;
								newMess[1] <= h1;
								currMess[1] <= h1;
								newMess[2] <= h2;
								currMess[2] <= h2;
								newMess[3] <= h3;
								currMess[3] <= h3;
								newMess[4] <= h4;
								currMess[4] <= h4;
								tInt <= 0;
							end
					end
				EXE: //performs shift and algorithm
					begin
						read_addr <= rraddr;
							if(!rrInit)
								begin
									if(cnt == 80)
										begin
											cnt3 <= 0;
										end
									else
										begin
											cnt3 <= cnt;
										end
									if(cnt < 16)
										begin
											W[cnt] <= wrd;
											currSize <= currLength;
											tInt <= 0;
										end
									else
										begin
											W[15] <= (wSft << 1)
													| (wSft >> 31);
											tInt=15;
										while(tInt > 0)
											begin
												W[tInt-1] <= W[tInt];
												tInt = tInt-1;
											end
									end
							if(cnt3 < 79)
								begin
									currMess[0] <= a1;
									currMess[1] <= b1;
									currMess[2] <= c1;
									currMess[3] <= d1;
									currMess[4] <= e1;
								end
							else
								begin
									if(currSize == size)
										begin
											state <=  IDLE;
										end
									else
										begin
											state <=  EXE;
										end
									newMess[0] <= a2;
									currMess[0] <= a2;
									newMess[1] <= b2;
									currMess[1] <= b2;
									newMess[2] <= c2;
									currMess[2] <= c2;
									newMess[3] <= d2;
									currMess[3] <= d2;
									newMess[4] <= e2;
									currMess[4] <= e2;
									currSize <= currLength;
									W[0] <= wrd;
								end
							end
						else
							begin
								rrInit <= rrInit - 1;

								if(rrInit == 2'b01)
								begin
									W[0] <= wrd;
									currSize <= currLength;
							end
						end
					end
			endcase
		end
	end

//appends length of message in bits as 64bit bigendian int
assign paddingSize = nbitword - ((messLength + (sbitword+1)) % 512);
assign size = messLength + 1 + paddingSize + sbitword;
assign rraddr = (((cnt3 > 13) & (cnt3 < 78)) | ( (cnt3 > 13) & (cnt3 < 78) & rrStp) | rrStp) ? read_addr : read_addr + 4;
assign wSft = (W[13] ^ W[8] ^ W[2] ^ W[0]);
assign rrStp =(messLength == currSize);


always@(*)
begin
//Padding
	if(size == currLength)
		begin
			wrd <= messLength;
		end
	else if((message_size - (currSize)/8 < 4))
		begin
			case(message_size % 4)
				0: wrd <= 32'b10000000000000000000000000000000;
				1: wrd <= rdwd & 32'b11111111000000000000000000000000
							| 32'b00000000100000000000000000000000;
				2: wrd <= rdwd & 32'b11111111111111110000000000000000
							| 32'b00000000000000001000000000000000;
				3: wrd <= rdwd & 32'b11111111111111111111111100000000
							| 32'b00000000000000000000000010000000;
			endcase
		end
	else if(messLength < currSize)
		begin
			wrd <= 32'h00000000;
		end
	else
		begin
			wrd <= rdwd;
		end

	//sets kt and computes F(B,C,D) and temp Values
	if(cnt3 >= 0  && cnt3 < 20)
		begin
			ktVal <= 32'h5a827999;
			bcdF <= ~(b0 | ~d0) | (b0 & c0);
		end
	else if(cnt3 >= 20 && cnt3 < 40)
		begin
			ktVal <= 32'h6ed9eba1;
			bcdF <= (b0 ^ c0 ^ d0);
		end
	else if(cnt3 >= 40 && cnt3 < 60)
		begin
			ktVal <= 32'h8f1bbcdc;
			bcdF <= ((b0 & c0) | b0 | c0) & ((b0 & c0) | d0);
		end
	else
		begin
			ktVal <= 32'hca62c1d6;
			bcdF <= (b0 ^ c0 ^ d0);
		end

		//temp result
		tWdVal <= {a0[26:0], a0[31:27]}
				+ bcdF
				+ W[currW]
				+ ktVal
				+ e0;
	end


assign rdwd = changeEndian(port_A_data_out);
assign done =  (state == IDLE) && (currSize-thrtwobit == size);
assign currLength = currSize + thrtwobit;
assign cnt = cnt3 + 1;
assign currW = ((((sbitword-1) >> 2)) > cnt3) ? cnt3 : 15;
assign messLength = message_size * btshft;


//Output Final Hash
assign hash = {newMess[0],newMess[1],newMess[2],newMess[3],newMess[4]};

endmodule
